//! The session handler: a sans-I/O state machine driving a single SOE session.
//!
//! This ports the reference `SoeProtocolHandler`, restructured as a pure state
//! machine. Rather than owning a socket, the handler accepts incoming datagrams via
//! [`SoeSession::process_incoming`], surfaces datagrams to be sent via
//! [`SoeSession::take_outgoing`], and surfaces received application data via
//! [`SoeSession::take_received`]. Time is supplied by the caller as [`Instant`].
//!
//! The handler negotiates a session (contextless [`SessionRequest`]/
//! [`SessionResponse`] exchange), then dispatches contextual packets: routing
//! reliable data to the input channel, acknowledgements to the output channel, and
//! handling heartbeats and disconnects.

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::channel::{
    InputConfig, OutputConfig, ReliableDataInputChannel, ReliableDataOutputChannel,
};
use crate::constants::{
    CRC_LENGTH, DEFAULT_SESSION_HEARTBEAT_AFTER, DEFAULT_SESSION_INACTIVITY_TIMEOUT,
    DEFAULT_UDP_LENGTH, SOE_PROTOCOL_VERSION,
};
use crate::crc32::Crc32;
use crate::io::{BinaryReader, BinaryWriter};
use crate::packet_utils::{ValidationResult, append_crc, read_op_code, validate_packet};
use crate::packets::{Acknowledge, AcknowledgeAll, Disconnect, SessionRequest, SessionResponse};
use crate::protocol::{DisconnectReason, OpCode};
use crate::rc4::Rc4KeyState;
use crate::varint::multi_packet;
use crate::zlib;

const OP_CODE_SIZE: usize = 2;
/// The default ACK wait used by the output channel.
const DEFAULT_ACK_WAIT: Duration = Duration::from_millis(500);

/// The mode a [`SoeSession`] operates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// The handler initiates the session (sends the [`SessionRequest`]).
    Client,
    /// The handler accepts a session (responds to a [`SessionRequest`]).
    Server,
}

/// The lifecycle state of a [`SoeSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The session is being negotiated.
    Negotiating,
    /// The session is established and exchanging data.
    Running,
    /// The session has terminated.
    Terminated,
}

/// An event surfaced by a [`SoeSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The session has been established and is ready to exchange data.
    Opened,
    /// The session has terminated for the given reason.
    Closed(DisconnectReason),
}

/// Parameters controlling a session. Mutated during negotiation as the two parties
/// agree on connection details.
#[derive(Debug, Clone)]
pub struct SessionParameters {
    /// The application protocol being proxied (must match between the two parties).
    pub application_protocol: String,
    /// The maximum UDP payload length this party can receive.
    pub udp_length: u32,
    /// The maximum UDP payload length the remote party can receive.
    pub remote_udp_length: u32,
    /// The seed used to compute packet CRCs (agreed during negotiation).
    pub crc_seed: u32,
    /// The number of bytes used to store a packet CRC (0..=4).
    pub crc_length: u8,
    /// Whether contextual packets may be compressed.
    pub is_compression_enabled: bool,
    /// The maximum number of incoming reliable data packets that may be queued.
    pub max_queued_incoming_reliable: u16,
    /// The maximum number of outgoing reliable data packets in flight at once.
    pub max_queued_outgoing_reliable: u16,
    /// The acknowledgement window used by the input channel.
    pub data_ack_window: u16,
    /// The interval after which to send a heartbeat (client only). `ZERO` disables.
    pub heartbeat_after: Duration,
    /// The interval after which to terminate an inactive session. `ZERO` disables.
    pub inactivity_timeout: Duration,
    /// Whether every incoming reliable data packet is acknowledged individually.
    pub acknowledge_all_data: bool,
    /// The maximum delay before acknowledging incoming reliable data sequences.
    pub max_ack_delay: Duration,
}

impl Default for SessionParameters {
    fn default() -> Self {
        Self {
            application_protocol: String::new(),
            udp_length: DEFAULT_UDP_LENGTH,
            remote_udp_length: DEFAULT_UDP_LENGTH,
            crc_seed: 0,
            crc_length: CRC_LENGTH,
            is_compression_enabled: false,
            max_queued_incoming_reliable: 256,
            max_queued_outgoing_reliable: 196,
            data_ack_window: 32,
            heartbeat_after: DEFAULT_SESSION_HEARTBEAT_AFTER,
            inactivity_timeout: DEFAULT_SESSION_INACTIVITY_TIMEOUT,
            acknowledge_all_data: false,
            max_ack_delay: Duration::from_millis(2),
        }
    }
}

/// Application-level parameters: the optional encryption key state.
#[derive(Debug, Clone, Default)]
pub struct ApplicationParameters {
    /// The RC4 key state used to (en/de)crypt application data, if encryption is
    /// enabled.
    pub encryption_key_state: Option<Rc4KeyState>,
}

/// A small linear-congruential generator used to produce session IDs and CRC seeds.
#[derive(Debug)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 32) as u32
    }
}

/// A sans-I/O handler for a single SOE protocol session.
#[derive(Debug)]
pub struct SoeSession {
    mode: SessionMode,
    state: SessionState,
    params: SessionParameters,

    input: ReliableDataInputChannel,
    output: ReliableDataOutputChannel,

    session_id: u32,
    termination_reason: DisconnectReason,
    terminated_by_remote: bool,
    open_session_on_next_packet: bool,
    last_received: Instant,

    rng: Lcg,

    outgoing: Vec<Bytes>,
    received: Vec<Bytes>,
    events: Vec<SessionEvent>,
}

impl SoeSession {
    /// Creates a new session handler in the [`SessionState::Negotiating`] state.
    ///
    /// `rng_seed` seeds the generator used for the session ID (client) and CRC seed
    /// (server); pass a fixed value for deterministic behaviour, or entropy for real
    /// sessions.
    pub fn new(
        mode: SessionMode,
        params: SessionParameters,
        app: ApplicationParameters,
        rng_seed: u64,
        now: Instant,
    ) -> Self {
        let input = ReliableDataInputChannel::new(
            InputConfig {
                max_queued_incoming: params.max_queued_incoming_reliable,
                acknowledge_all_data: params.acknowledge_all_data,
                data_ack_window: params.data_ack_window,
                max_ack_delay: params.max_ack_delay,
            },
            app.encryption_key_state.clone(),
            now,
        );

        let mut output = ReliableDataOutputChannel::new(
            OutputConfig {
                max_data_length: Self::max_data_length(&params),
                max_queued_outgoing: params.max_queued_outgoing_reliable as usize,
                ack_wait: DEFAULT_ACK_WAIT,
            },
            app.encryption_key_state.clone(),
            now,
        );
        output.set_max_data_length(Self::max_data_length(&params));

        Self {
            mode,
            state: SessionState::Negotiating,
            params,
            input,
            output,
            session_id: 0,
            termination_reason: DisconnectReason::None,
            terminated_by_remote: false,
            open_session_on_next_packet: false,
            last_received: now,
            rng: Lcg::new(rng_seed),
            outgoing: Vec::new(),
            received: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Returns the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session mode.
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// Returns the negotiated session ID.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Returns the negotiated CRC seed (meaningful once running).
    pub fn crc_seed(&self) -> u32 {
        self.params.crc_seed
    }

    /// Returns the reason the session terminated (meaningful once terminated).
    pub fn termination_reason(&self) -> DisconnectReason {
        self.termination_reason
    }

    /// Returns whether the termination was initiated by the remote party.
    pub fn terminated_by_remote(&self) -> bool {
        self.terminated_by_remote
    }

    /// Drains datagrams that the caller should send to the remote.
    pub fn take_outgoing(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.outgoing)
    }

    /// Drains application data received from the remote.
    pub fn take_received(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.received)
    }

    /// Drains session lifecycle events.
    pub fn take_events(&mut self) -> Vec<SessionEvent> {
        std::mem::take(&mut self.events)
    }

    fn max_data_length(params: &SessionParameters) -> usize {
        params.udp_length as usize
            - OP_CODE_SIZE
            - params.is_compression_enabled as usize
            - params.crc_length as usize
    }

    /// Sends a [`SessionRequest`] to begin negotiation. Only valid in client mode
    /// while negotiating.
    pub fn send_session_request(&mut self) {
        if self.state != SessionState::Negotiating || self.mode != SessionMode::Client {
            return;
        }

        let id = self.rng.next_u32();
        self.session_id = id;
        let request = SessionRequest {
            soe_protocol_version: SOE_PROTOCOL_VERSION,
            session_id: id,
            udp_length: self.params.udp_length,
            application_protocol: self.params.application_protocol.clone(),
        };

        let mut buf = vec![0u8; request.size()];
        let n = request.serialize(&mut buf).expect("session request buffer");
        buf.truncate(n);
        self.outgoing.push(Bytes::from(buf));
    }

    /// Enqueues application data to be sent reliably. Returns `false` if the session
    /// is not running.
    #[must_use = "a false return means the data was dropped because the session is not running"]
    pub fn enqueue_data(&mut self, data: &[u8]) -> bool {
        if self.state != SessionState::Running {
            return false;
        }
        self.output.enqueue_data(data);
        true
    }

    /// Terminates the session, optionally notifying the remote.
    pub fn terminate(&mut self, reason: DisconnectReason, notify_remote: bool, now: Instant) {
        self.terminate_inner(reason, notify_remote, false, now);
    }

    /// Processes a single incoming datagram from the remote.
    pub fn process_incoming(&mut self, datagram: Bytes, now: Instant) {
        if self.state == SessionState::Terminated {
            return;
        }

        let crc = Crc32::new(self.params.crc_seed);
        let (result, op) = validate_packet(
            &datagram,
            &crc,
            self.params.crc_length,
            self.params.is_compression_enabled,
        );

        if result != ValidationResult::Valid {
            self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
            return;
        }
        let op = op.expect("valid packet has an op code");

        if self.open_session_on_next_packet {
            self.events.push(SessionEvent::Opened);
            self.open_session_on_next_packet = false;
        }

        // Set after validation, as a primitive guard against a stream of corrupt
        // packets keeping a session alive.
        self.last_received = now;

        let body = datagram.slice(OP_CODE_SIZE..);
        if op.is_contextless() {
            self.handle_contextless(op, &body, now);
        } else {
            let crc_length = self.params.crc_length as usize;
            let body = body.slice(..body.len() - crc_length);
            self.handle_contextual(op, body, now);
        }

        self.flush_channels(now);
    }

    /// Runs a single tick of the session: heartbeats, inactivity timeout, and the
    /// reliable data channels.
    pub fn run_tick(&mut self, now: Instant) {
        if self.state == SessionState::Terminated {
            return;
        }

        self.send_heartbeat_if_required(now);

        if !self.params.inactivity_timeout.is_zero()
            && now.duration_since(self.last_received) > self.params.inactivity_timeout
        {
            self.terminate_inner(DisconnectReason::Timeout, false, false, now);
            return;
        }

        self.input.run_tick(now);
        self.output.run_tick(now);
        self.flush_channels(now);
    }

    fn handle_contextless(&mut self, op: OpCode, body: &[u8], now: Instant) {
        match op {
            OpCode::SessionRequest => self.handle_session_request(body, now),
            OpCode::SessionResponse => self.handle_session_response(body, now),
            OpCode::UnknownSender => {
                self.terminate_inner(DisconnectReason::UnreachableConnection, false, false, now);
            }
            // Remap requests are the responsibility of a connection manager (Phase 7).
            _ => {}
        }
    }

    fn handle_session_request(&mut self, body: &[u8], now: Instant) {
        if self.mode == SessionMode::Client {
            self.terminate_inner(DisconnectReason::ConnectingToSelf, false, false, now);
            return;
        }

        let request = match SessionRequest::deserialize(body, false) {
            Ok(r) => r,
            Err(_) => {
                self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                return;
            }
        };

        self.params.remote_udp_length = request.udp_length;
        self.session_id = request.session_id;

        if self.state != SessionState::Negotiating {
            self.terminate_inner(DisconnectReason::ConnectError, true, false, now);
            return;
        }

        let protocols_match = request.soe_protocol_version == SOE_PROTOCOL_VERSION
            && request.application_protocol == self.params.application_protocol;
        if !protocols_match {
            self.terminate_inner(DisconnectReason::ProtocolMismatch, true, false, now);
            return;
        }

        self.params.crc_length = CRC_LENGTH;
        self.params.crc_seed = self.rng.next_u32();
        self.output
            .set_max_data_length(Self::max_data_length(&self.params));

        let response = SessionResponse {
            session_id: self.session_id,
            crc_seed: self.params.crc_seed,
            crc_length: self.params.crc_length,
            is_compression_enabled: self.params.is_compression_enabled,
            unknown_value_1: 0,
            udp_length: self.params.udp_length,
            soe_protocol_version: SOE_PROTOCOL_VERSION,
        };

        let mut buf = [0u8; SessionResponse::SIZE];
        let n = response
            .serialize(&mut buf)
            .expect("session response buffer");
        self.outgoing.push(Bytes::copy_from_slice(&buf[..n]));

        self.state = SessionState::Running;
        self.open_session_on_next_packet = true;
    }

    fn handle_session_response(&mut self, body: &[u8], now: Instant) {
        if self.mode == SessionMode::Server {
            self.terminate_inner(DisconnectReason::ConnectingToSelf, false, false, now);
            return;
        }

        let response = match SessionResponse::deserialize(body, false) {
            Ok(r) => r,
            Err(_) => {
                self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                return;
            }
        };

        if self.state != SessionState::Negotiating {
            self.terminate_inner(DisconnectReason::ConnectError, true, false, now);
            return;
        }

        if response.soe_protocol_version != SOE_PROTOCOL_VERSION {
            self.terminate_inner(DisconnectReason::ProtocolMismatch, true, false, now);
            return;
        }

        self.params.remote_udp_length = response.udp_length;
        self.params.crc_length = response.crc_length;
        self.params.crc_seed = response.crc_seed;
        self.params.is_compression_enabled = response.is_compression_enabled;
        self.session_id = response.session_id;
        self.output
            .set_max_data_length(Self::max_data_length(&self.params));

        self.state = SessionState::Running;
        self.events.push(SessionEvent::Opened);
    }

    fn handle_contextual(&mut self, op: OpCode, body: Bytes, now: Instant) {
        let body = if self.params.is_compression_enabled {
            if body.is_empty() {
                return;
            }
            let is_compressed = body[0] > 0;
            let rest = body.slice(1..);
            if is_compressed {
                match zlib::inflate(&rest) {
                    Ok(d) => Bytes::from(d),
                    Err(_) => {
                        self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                        return;
                    }
                }
            } else {
                rest
            }
        } else {
            body
        };

        self.handle_contextual_inner(op, body, now);
    }

    fn handle_contextual_inner(&mut self, op: OpCode, body: Bytes, now: Instant) {
        match op {
            OpCode::MultiPacket => {
                let mut offset = 0;
                while offset < body.len() {
                    let mut reader = BinaryReader::new(&body[offset..]);
                    let len = match multi_packet::read(&mut reader) {
                        Ok(l) => l as usize,
                        Err(_) => {
                            self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                            return;
                        }
                    };
                    // Advance past the length varint by however many bytes it used.
                    offset += reader.offset();

                    if len < OP_CODE_SIZE || len > body.len() - offset {
                        self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                        return;
                    }

                    let sub = body.slice(offset..offset + len);
                    let sub_op = match read_op_code(&sub) {
                        Some(o) => o,
                        None => {
                            self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                            return;
                        }
                    };
                    self.handle_contextual_inner(sub_op, sub.slice(OP_CODE_SIZE..), now);
                    offset += len;

                    // A sub-packet may have terminated the session (e.g. a corrupt
                    // fragment or an embedded Disconnect). Stop draining the bundle
                    // rather than processing data on a dead session.
                    if self.state == SessionState::Terminated {
                        return;
                    }
                }
            }
            OpCode::Disconnect => {
                if let Ok(disconnect) = Disconnect::deserialize(&body) {
                    self.terminate_inner(disconnect.reason, false, true, now);
                }
            }
            OpCode::Heartbeat if self.mode == SessionMode::Server => {
                let dg = self.frame_contextual(OpCode::Heartbeat, &[]);
                self.outgoing.push(dg);
            }
            OpCode::ReliableData => {
                let outcome = self.input.handle_reliable_data(body, now);
                if outcome.is_err() {
                    self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                }
            }
            OpCode::ReliableDataFragment => {
                let outcome = self.input.handle_reliable_data_fragment(body, now);
                if outcome.is_err() {
                    self.terminate_inner(DisconnectReason::CorruptPacket, true, false, now);
                }
            }
            OpCode::Acknowledge => {
                if let Ok(ack) = Acknowledge::deserialize(&body) {
                    self.output.notify_of_acknowledge(ack.sequence, now);
                }
            }
            OpCode::AcknowledgeAll => {
                if let Ok(ack) = AcknowledgeAll::deserialize(&body) {
                    self.output.notify_of_acknowledge_all(ack.sequence, now);
                }
            }
            _ => {}
        }
    }

    fn send_heartbeat_if_required(&mut self, now: Instant) {
        let may_send = self.mode == SessionMode::Client
            && self.state == SessionState::Running
            && !self.params.heartbeat_after.is_zero()
            && now.duration_since(self.last_received) > self.params.heartbeat_after;

        if may_send {
            let dg = self.frame_contextual(OpCode::Heartbeat, &[]);
            self.outgoing.push(dg);
        }
    }

    fn flush_channels(&mut self, _now: Instant) {
        for ack in self.input.take_outgoing() {
            let payload = ack.sequence.to_be_bytes();
            let dg = self.frame_contextual(ack.op_code, &payload);
            self.outgoing.push(dg);
        }

        for packet in self.output.take_outgoing() {
            let dg = self.frame_contextual(packet.op_code, &packet.payload);
            self.outgoing.push(dg);
        }

        for data in self.input.take_app_data() {
            self.received.push(data);
        }
    }

    /// Frames a contextual packet: OP code, optional compression flag, payload, and
    /// CRC.
    fn frame_contextual(&self, op: OpCode, payload: &[u8]) -> Bytes {
        let compression = self.params.is_compression_enabled as usize;
        let crc_length = self.params.crc_length as usize;
        let capacity = OP_CODE_SIZE + compression + payload.len() + crc_length;

        let mut buf = vec![0u8; capacity];
        let written = {
            let mut w = BinaryWriter::new(&mut buf);
            w.write_u16(op.as_u16()).expect("op code");
            if self.params.is_compression_enabled {
                w.write_bool(false).expect("compression flag");
            }
            w.write_bytes(payload).expect("payload");
            w.offset()
        };

        let crc = Crc32::new(self.params.crc_seed);
        let total = append_crc(&mut buf, written, &crc, self.params.crc_length).expect("crc");
        buf.truncate(total);
        Bytes::from(buf)
    }

    fn terminate_inner(
        &mut self,
        reason: DisconnectReason,
        notify_remote: bool,
        terminated_by_remote: bool,
        now: Instant,
    ) {
        if self.state == SessionState::Terminated {
            return;
        }

        // Naive flush of the output channel.
        self.output.run_tick(now);
        self.flush_channels(now);
        self.termination_reason = reason;

        if notify_remote && self.state == SessionState::Running {
            let disconnect = Disconnect::new(self.session_id, reason);
            let mut payload = [0u8; Disconnect::SIZE];
            let n = disconnect
                .serialize(&mut payload)
                .expect("disconnect buffer");
            let dg = self.frame_contextual(OpCode::Disconnect, &payload[..n]);
            self.outgoing.push(dg);
        }

        self.state = SessionState::Terminated;
        self.terminated_by_remote = terminated_by_remote;
        self.events.push(SessionEvent::Closed(reason));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(protocol: &str) -> SessionParameters {
        SessionParameters {
            application_protocol: protocol.to_owned(),
            // Keep the window small so fragmentation/windowing is exercised.
            max_queued_incoming_reliable: 32,
            max_queued_outgoing_reliable: 32,
            // Disable heartbeats/timeouts for deterministic tests.
            heartbeat_after: Duration::ZERO,
            inactivity_timeout: Duration::ZERO,
            ..SessionParameters::default()
        }
    }

    /// Drives a full negotiation handshake, returning the two running sessions.
    fn negotiate(now: Instant) -> (SoeSession, SoeSession) {
        let mut client = SoeSession::new(
            SessionMode::Client,
            params("TestProtocol"),
            ApplicationParameters::default(),
            1,
            now,
        );
        let mut server = SoeSession::new(
            SessionMode::Server,
            params("TestProtocol"),
            ApplicationParameters::default(),
            2,
            now,
        );

        client.send_session_request();
        pump(&mut client, &mut server, now);

        (client, server)
    }

    /// Moves all queued datagrams between the two sessions until neither has any
    /// more to send.
    fn pump(a: &mut SoeSession, b: &mut SoeSession, now: Instant) {
        loop {
            let from_a = a.take_outgoing();
            let from_b = b.take_outgoing();
            if from_a.is_empty() && from_b.is_empty() {
                break;
            }
            for dg in from_a {
                b.process_incoming(dg, now);
            }
            for dg in from_b {
                a.process_incoming(dg, now);
            }
        }
    }

    fn generate(size: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678 ^ size as u32;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn negotiation_establishes_running_session() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        assert_eq!(client.state(), SessionState::Running);
        assert_eq!(server.state(), SessionState::Running);
        assert_eq!(client.session_id(), server.session_id());
        // Both parties agreed on the server's CRC seed.
        assert_ne!(server.params.crc_seed, 0);
        assert_eq!(client.params.crc_seed, server.params.crc_seed);

        assert!(client.take_events().contains(&SessionEvent::Opened));
        // The server only opens the session once it receives its first packet after
        // sending the response (matching the C# reference). Drive one more packet.
        assert!(client.enqueue_data(b"hi"));
        client.run_tick(now);
        pump(&mut client, &mut server, now);
        assert!(server.take_events().contains(&SessionEvent::Opened));
    }

    #[test]
    fn protocol_mismatch_terminates() {
        let now = Instant::now();
        let mut client = SoeSession::new(
            SessionMode::Client,
            params("ClientProtocol"),
            ApplicationParameters::default(),
            1,
            now,
        );
        let mut server = SoeSession::new(
            SessionMode::Server,
            params("ServerProtocol"),
            ApplicationParameters::default(),
            2,
            now,
        );

        client.send_session_request();
        pump(&mut client, &mut server, now);

        assert_eq!(server.state(), SessionState::Terminated);
        assert_eq!(
            server.termination_reason(),
            DisconnectReason::ProtocolMismatch
        );
        // The server rejects before a CRC seed is agreed, so it cannot send a valid
        // contextual Disconnect; the client stays in negotiation and would later time
        // out (matching the C# reference, which only notifies the remote when Running).
        assert_eq!(client.state(), SessionState::Negotiating);
    }

    #[test]
    fn round_trips_small_and_large_data() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        let small = generate(5);
        let large = generate(2000); // forces fragmentation

        assert!(client.enqueue_data(&small));
        assert!(client.enqueue_data(&large));

        client.run_tick(now);
        pump(&mut client, &mut server, now);

        let received = server.take_received();
        assert_eq!(received.len(), 2);
        assert_eq!(&received[0][..], &small[..]);
        assert_eq!(&received[1][..], &large[..]);
    }

    #[test]
    fn round_trips_data_both_directions() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        let to_server = generate(1500);
        let to_client = generate(800);

        assert!(client.enqueue_data(&to_server));
        assert!(server.enqueue_data(&to_client));
        client.run_tick(now);
        server.run_tick(now);
        pump(&mut client, &mut server, now);

        assert_eq!(&server.take_received()[0][..], &to_server[..]);
        assert_eq!(&client.take_received()[0][..], &to_client[..]);
    }

    /// A `MultiPacket` bundle whose first sub-packet corrupts the session must not
    /// have its remaining sub-packets processed: once a sub-packet terminates the
    /// session, the bundle loop short-circuits rather than delivering data on a dead
    /// session.
    #[test]
    fn multi_packet_stops_after_sub_packet_terminates() {
        let now = Instant::now();
        let (_client, mut server) = negotiate(now);
        assert_eq!(server.state(), SessionState::Running);

        // Build a MultiPacket body with two sub-packets:
        //   1. a corrupt master ReliableDataFragment (only 2 of the required 4
        //      total-length bytes) -> terminates the session as CorruptPacket;
        //   2. an otherwise-valid ReliableData carrying "hi".
        // Each sub-packet is `[length][op-code (2 BE)][sub-payload]`; lengths < 256
        // encode as a single byte.
        let mut body = Vec::new();

        // Sub-packet 1: ReliableDataFragment, sequence 0, truncated length prefix.
        let sub1 = [0x00, 0x0D, 0x00, 0x00, 0xAB, 0xCD];
        body.push(sub1.len() as u8);
        body.extend_from_slice(&sub1);

        // Sub-packet 2: ReliableData, sequence 0, payload "hi".
        let sub2 = [0x00, 0x09, 0x00, 0x00, b'h', b'i'];
        body.push(sub2.len() as u8);
        body.extend_from_slice(&sub2);

        server.handle_contextual_inner(OpCode::MultiPacket, Bytes::from(body), now);

        assert_eq!(server.state(), SessionState::Terminated);
        assert_eq!(server.termination_reason(), DisconnectReason::CorruptPacket);
        // The second sub-packet must never have reached the input channel.
        assert!(
            server.input.take_app_data().is_empty(),
            "data after a terminating sub-packet was processed"
        );
    }

    #[test]
    fn disconnect_notifies_remote() {
        let now = Instant::now();
        let (mut client, mut server) = negotiate(now);

        client.terminate(DisconnectReason::Application, true, now);
        assert_eq!(client.state(), SessionState::Terminated);

        pump(&mut client, &mut server, now);
        assert_eq!(server.state(), SessionState::Terminated);
        assert_eq!(server.termination_reason(), DisconnectReason::Application);
        assert!(server.terminated_by_remote());
    }

    #[test]
    fn encrypted_data_round_trips() {
        let now = Instant::now();
        let key = Rc4KeyState::new(&[1, 2, 3, 4, 5]);
        let app = ApplicationParameters {
            encryption_key_state: Some(key),
        };

        let mut client = SoeSession::new(
            SessionMode::Client,
            params("TestProtocol"),
            app.clone(),
            1,
            now,
        );
        let mut server = SoeSession::new(SessionMode::Server, params("TestProtocol"), app, 2, now);

        client.send_session_request();
        pump(&mut client, &mut server, now);

        let data = generate(1200);
        assert!(client.enqueue_data(&data));
        client.run_tick(now);
        pump(&mut client, &mut server, now);

        assert_eq!(&server.take_received()[0][..], &data[..]);
    }
}
