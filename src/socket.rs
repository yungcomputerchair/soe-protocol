//! The socket handler: a sans-I/O multiplexer of SOE sessions over a single UDP
//! socket, plus a thin, dependency-free transport adapter to drive it.
//!
//! This ports the reference `SoeSocketHandler`, restructured to keep the core a
//! pure state machine. [`SoeMultiplexer`] owns no socket: it accepts incoming
//! datagrams tagged with their remote address via
//! [`SoeMultiplexer::process_incoming`], surfaces datagrams to send (each tagged
//! with a destination address) via [`SoeMultiplexer::take_outgoing`], and surfaces
//! session lifecycle and data events via [`SoeMultiplexer::take_events`]. Time is
//! supplied by the caller as an [`Instant`].
//!
//! The multiplexer is generic over the address type so that it never depends on any
//! particular socket implementation. For convenience, [`UdpTransport`] abstracts a
//! non-blocking UDP socket and [`SoeMultiplexer::drive`] runs a single
//! read/tick/send step over any such transport — including the blanket
//! implementation provided here for [`std::net::UdpSocket`], which pulls in no async
//! runtime.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;

use crate::packet_utils::read_op_code;
use crate::packets::RemapConnection;
use crate::protocol::{DisconnectReason, OpCode};
use crate::session::{
    ApplicationParameters, SessionEvent, SessionMode, SessionParameters, SessionState, SoeSession,
};

/// A driver-agnostic surface for managing SOE sessions over a UDP socket.
///
/// Implemented by the concrete socket drivers — [`crate::sync_rt::SyncSoeSocket`]
/// and (with the `tokio` feature) [`crate::tokio_rt::TokioSoeSocket`] — so that
/// application code can be written generically over the driver.
///
/// The I/O drive step itself differs between drivers (a blocking `step` versus an
/// `async fn step`) and so is provided as an inherent method on each type rather
/// than on this trait.
pub trait SoeSocket {
    /// Returns the local address the underlying socket is bound to.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    /// Returns the number of active sessions.
    fn session_count(&self) -> usize;

    /// Opens a client session to `remote`. The session request is sent on the next
    /// drive step.
    fn connect(&mut self, remote: SocketAddr);

    /// Enqueues application data to be sent reliably to `remote`. Returns `false` if
    /// there is no running session for that address.
    fn enqueue_data(&mut self, remote: &SocketAddr, data: &[u8]) -> bool;

    /// Terminates the session with `remote`, notifying the remote party.
    fn terminate(&mut self, remote: &SocketAddr, reason: DisconnectReason);
}

/// An address that can key a session in a [`SoeMultiplexer`].
///
/// The [`same_host`](RemoteAddr::same_host) method lets the multiplexer honour the
/// reference's port-remap security rule (only the port of an established session may
/// change, never the host) without hard-coding a concrete address type.
pub trait RemoteAddr: Clone + Eq + Hash {
    /// Returns whether `self` and `other` refer to the same host, ignoring any port
    /// component. Used to guard port remaps against session hijacking.
    fn same_host(&self, other: &Self) -> bool;
}

impl RemoteAddr for SocketAddr {
    fn same_host(&self, other: &Self) -> bool {
        self.ip() == other.ip()
    }
}

/// Options controlling a [`SoeMultiplexer`].
#[derive(Debug, Clone, Default)]
pub struct SocketConfig {
    /// The session parameters used when creating new sessions.
    pub default_session_params: SessionParameters,
    /// The application parameters (e.g. encryption key) cloned into each session.
    pub app_params: ApplicationParameters,
    /// Whether established sessions are permitted to remap to a new port.
    pub allow_port_remaps: bool,
    /// The base seed used to derive each new session's RNG seed. Successive sessions
    /// receive successive seeds, keeping behaviour deterministic for a given base.
    pub base_rng_seed: u64,
}

/// An event surfaced by a [`SoeMultiplexer`], tagged with the remote it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketEvent<A> {
    /// A session with `remote` has been established.
    SessionOpened {
        /// The remote address of the opened session.
        remote: A,
    },
    /// Application data was received from `remote`.
    DataReceived {
        /// The remote address the data came from.
        remote: A,
        /// The received application data.
        data: Bytes,
    },
    /// A session with `remote` has terminated for the given reason.
    SessionClosed {
        /// The remote address of the closed session.
        remote: A,
        /// The reason the session terminated.
        reason: DisconnectReason,
    },
}

/// A sans-I/O multiplexer of SOE sessions, keyed by remote address.
pub struct SoeMultiplexer<A: RemoteAddr> {
    config: SocketConfig,
    sessions: HashMap<A, SoeSession>,
    outgoing: Vec<(A, Bytes)>,
    events: Vec<SocketEvent<A>>,
    next_seed: u64,
}

impl<A: RemoteAddr> SoeMultiplexer<A> {
    /// Creates a new, empty multiplexer.
    pub fn new(config: SocketConfig) -> Self {
        let next_seed = config.base_rng_seed;
        Self {
            config,
            sessions: HashMap::new(),
            outgoing: Vec::new(),
            events: Vec::new(),
            next_seed,
        }
    }

    /// Returns the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns a reference to the session for `remote`, if one exists.
    pub fn session(&self, remote: &A) -> Option<&SoeSession> {
        self.sessions.get(remote)
    }

    /// Drains datagrams to be sent, each tagged with its destination address.
    pub fn take_outgoing(&mut self) -> Vec<(A, Bytes)> {
        std::mem::take(&mut self.outgoing)
    }

    /// Drains accumulated session events.
    pub fn take_events(&mut self) -> Vec<SocketEvent<A>> {
        std::mem::take(&mut self.events)
    }

    /// Opens a client session to `remote` and sends the initial session request.
    pub fn connect(&mut self, remote: A, now: Instant) {
        self.create_session(remote.clone(), SessionMode::Client, now);
        if let Some(session) = self.sessions.get_mut(&remote) {
            session.send_session_request();
        }
        self.drain_session(&remote);
    }

    /// Enqueues application data to be sent reliably to `remote`. Returns `false` if
    /// there is no running session for that address.
    pub fn enqueue_data(&mut self, remote: &A, data: &[u8]) -> bool {
        let queued = match self.sessions.get_mut(remote) {
            Some(session) => session.enqueue_data(data),
            None => false,
        };
        self.drain_session(remote);
        queued
    }

    /// Terminates the session with `remote`, notifying the remote party.
    pub fn terminate(&mut self, remote: &A, reason: DisconnectReason, now: Instant) {
        if let Some(session) = self.sessions.get_mut(remote) {
            session.terminate(reason, true, now);
        }
        self.drain_session(remote);
        self.remove_if_terminated(remote);
    }

    /// Processes a single datagram received from `remote`.
    pub fn process_incoming(&mut self, remote: A, datagram: Bytes, now: Instant) {
        if !self.sessions.contains_key(&remote) {
            match read_op_code(&datagram) {
                Some(OpCode::SessionRequest) => {
                    self.create_session(remote.clone(), SessionMode::Server, now);
                }
                Some(OpCode::RemapConnection) => {
                    self.handle_remap(&remote, &datagram);
                    return;
                }
                // No session and not an opener: nothing we can do with this datagram.
                _ => return,
            }
        }

        if let Some(session) = self.sessions.get_mut(&remote) {
            session.process_incoming(datagram, now);
        }
        self.drain_session(&remote);
        self.remove_if_terminated(&remote);
    }

    /// Runs a single tick over every session: heartbeats, timeouts, and the reliable
    /// data channels. Terminated sessions are removed (after their final events are
    /// surfaced).
    pub fn run_tick(&mut self, now: Instant) {
        // Drain directly into the multiplexer's buffers during a single retain pass,
        // removing terminated sessions in the same sweep. Taking the buffers out of
        // `self` lets the retain closure borrow them without conflicting with the
        // `&mut self.sessions` retain holds.
        let mut outgoing = std::mem::take(&mut self.outgoing);
        let mut events = std::mem::take(&mut self.events);

        self.sessions.retain(|remote, session| {
            session.run_tick(now);
            Self::drain_into(remote, session, &mut outgoing, &mut events);
            session.state() != SessionState::Terminated
        });

        self.outgoing = outgoing;
        self.events = events;
    }

    /// Runs a single read/tick/send step over `transport`: drains all immediately
    /// available datagrams, runs a tick, and flushes outgoing datagrams.
    ///
    /// Datagrams larger than 2048 bytes are not supported by this helper; SOE UDP
    /// lengths default to 512 and rarely exceed it.
    pub fn drive<T>(&mut self, transport: &mut T, now: Instant) -> std::io::Result<()>
    where
        T: UdpTransport<Addr = A>,
    {
        let mut buf = [0u8; 2048];
        while let Some((len, from)) = transport.try_recv(&mut buf)? {
            self.process_incoming(from, Bytes::copy_from_slice(&buf[..len]), now);
        }

        self.run_tick(now);

        for (addr, datagram) in self.take_outgoing() {
            transport.send_to(&datagram, &addr)?;
        }
        Ok(())
    }

    fn create_session(&mut self, remote: A, mode: SessionMode, now: Instant) {
        let seed = self.next_seed;
        self.next_seed = self.next_seed.wrapping_add(1);

        let session = SoeSession::new(
            mode,
            self.config.default_session_params.clone(),
            self.config.app_params.clone(),
            seed,
            now,
        );
        self.sessions.insert(remote, session);
    }

    fn handle_remap(&mut self, from: &A, datagram: &[u8]) {
        if !self.config.allow_port_remaps {
            return;
        }

        let remap = match RemapConnection::deserialize(datagram, true) {
            Ok(remap) => remap,
            Err(_) => return,
        };

        let old_key = self.sessions.iter().find_map(|(key, session)| {
            (session.session_id() == remap.session_id && session.crc_seed() == remap.crc_seed)
                .then(|| key.clone())
        });
        let Some(old_key) = old_key else { return };

        // Only a port change is acceptable; a differing host is likely a hijack.
        if &old_key == from || !old_key.same_host(from) {
            return;
        }

        if let Some(session) = self.sessions.remove(&old_key) {
            self.sessions.insert(from.clone(), session);
        }
    }

    fn drain_session(&mut self, remote: &A) {
        if let Some(session) = self.sessions.get_mut(remote) {
            Self::drain_into(remote, session, &mut self.outgoing, &mut self.events);
        }
    }

    /// Moves a session's pending datagrams, received data, and events into the given
    /// multiplexer buffers, tagging each with `remote`.
    ///
    /// Events are ordered so that a session's [`SocketEvent::SessionOpened`] is always
    /// surfaced before any of its [`SocketEvent::DataReceived`], and its
    /// [`SocketEvent::SessionClosed`] always after. This lets consumers that key
    /// per-session state on lifecycle events (e.g. spawning a task on open) reliably
    /// have that state in place before the session's data arrives.
    fn drain_into(
        remote: &A,
        session: &mut SoeSession,
        outgoing: &mut Vec<(A, Bytes)>,
        events: &mut Vec<SocketEvent<A>>,
    ) {
        for datagram in session.take_outgoing() {
            outgoing.push((remote.clone(), datagram));
        }

        let session_events = session.take_events();

        for event in &session_events {
            if matches!(event, SessionEvent::Opened) {
                events.push(SocketEvent::SessionOpened {
                    remote: remote.clone(),
                });
            }
        }

        for data in session.take_received() {
            events.push(SocketEvent::DataReceived {
                remote: remote.clone(),
                data,
            });
        }

        for event in session_events {
            if let SessionEvent::Closed(reason) = event {
                events.push(SocketEvent::SessionClosed {
                    remote: remote.clone(),
                    reason,
                });
            }
        }
    }

    fn remove_if_terminated(&mut self, remote: &A) {
        if let Some(session) = self.sessions.get(remote)
            && session.state() == SessionState::Terminated
        {
            self.sessions.remove(remote);
        }
    }
}

/// A non-blocking UDP transport that a [`SoeMultiplexer`] can be driven over.
///
/// Implementations should not block: [`try_recv`](UdpTransport::try_recv) returns
/// `Ok(None)` when no datagram is immediately available.
pub trait UdpTransport {
    /// The address type identifying remote peers.
    type Addr: RemoteAddr;

    /// Attempts to receive a single datagram without blocking. Returns `Ok(None)` if
    /// none is available, or `Ok(Some((len, from)))` on success.
    fn try_recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<(usize, Self::Addr)>>;

    /// Sends `buf` to `addr`, returning the number of bytes sent.
    fn send_to(&mut self, buf: &[u8], addr: &Self::Addr) -> std::io::Result<usize>;
}

impl UdpTransport for std::net::UdpSocket {
    type Addr = std::net::SocketAddr;

    fn try_recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<(usize, Self::Addr)>> {
        match self.recv_from(buf) {
            Ok((len, from)) => Ok(Some((len, from))),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn send_to(&mut self, buf: &[u8], addr: &Self::Addr) -> std::io::Result<usize> {
        std::net::UdpSocket::send_to(self, buf, addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rc4::Rc4KeyState;
    use std::net::SocketAddr;

    const CLIENT: &str = "127.0.0.1:4001";
    const SERVER: &str = "127.0.0.1:4002";

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn config(protocol: &str, seed: u64) -> SocketConfig {
        let mut params = SessionParameters {
            application_protocol: protocol.to_owned(),
            ..SessionParameters::default()
        };
        params.heartbeat_after = std::time::Duration::ZERO;
        params.inactivity_timeout = std::time::Duration::ZERO;
        SocketConfig {
            default_session_params: params,
            app_params: ApplicationParameters::default(),
            allow_port_remaps: false,
            base_rng_seed: seed,
        }
    }

    /// Exchanges datagrams between two multiplexers until both fall silent. `client`
    /// reaches `server` at `SERVER`; `server` sees the client at `CLIENT`.
    fn pump(client: &mut SoeMultiplexer<SocketAddr>, server: &mut SoeMultiplexer<SocketAddr>) {
        let now = Instant::now();
        for _ in 0..64 {
            // Tick first so any enqueued data is dispatched into the outgoing queue.
            client.run_tick(now);
            server.run_tick(now);

            let from_client = client.take_outgoing();
            let from_server = server.take_outgoing();
            if from_client.is_empty() && from_server.is_empty() {
                break;
            }
            for (_dest, dg) in from_client {
                server.process_incoming(addr(CLIENT), dg, now);
            }
            for (_dest, dg) in from_server {
                client.process_incoming(addr(SERVER), dg, now);
            }
        }
    }

    #[test]
    fn establishes_session_and_emits_opened() {
        let now = Instant::now();
        let mut client = SoeMultiplexer::new(config("TestProtocol", 1));
        let mut server = SoeMultiplexer::new(config("TestProtocol", 2));

        client.connect(addr(SERVER), now);
        pump(&mut client, &mut server);

        assert_eq!(client.session_count(), 1);
        assert_eq!(server.session_count(), 1);
        assert!(client.take_events().iter().any(|e| matches!(
            e,
            SocketEvent::SessionOpened { remote } if *remote == addr(SERVER)
        )));

        // The server opens its session on the first packet after responding, so nudge
        // it with a data packet from the client.
        client.enqueue_data(&addr(SERVER), b"hi");
        pump(&mut client, &mut server);
        assert!(server.take_events().iter().any(|e| matches!(
            e,
            SocketEvent::SessionOpened { remote } if *remote == addr(CLIENT)
        )));
    }

    #[test]
    fn routes_data_between_peers() {
        let mut client = SoeMultiplexer::new(config("TestProtocol", 1));
        let mut server = SoeMultiplexer::new(config("TestProtocol", 2));

        client.connect(addr(SERVER), Instant::now());
        pump(&mut client, &mut server);

        assert!(client.enqueue_data(&addr(SERVER), b"ping"));
        pump(&mut client, &mut server);
        assert!(server.take_events().iter().any(|e| matches!(
            e,
            SocketEvent::DataReceived { remote, data } if *remote == addr(CLIENT) && data == "ping"
        )));

        assert!(server.enqueue_data(&addr(CLIENT), b"pong"));
        pump(&mut client, &mut server);
        assert!(client.take_events().iter().any(|e| matches!(
            e,
            SocketEvent::DataReceived { remote, data } if *remote == addr(SERVER) && data == "pong"
        )));
    }

    #[test]
    fn encrypted_data_routes_between_peers() {
        let key = Rc4KeyState::new(&[1, 2, 3, 4, 5]);
        let mut client_cfg = config("TestProtocol", 1);
        let mut server_cfg = config("TestProtocol", 2);
        client_cfg.app_params.encryption_key_state = Some(key.clone());
        server_cfg.app_params.encryption_key_state = Some(key);

        let mut client = SoeMultiplexer::new(client_cfg);
        let mut server = SoeMultiplexer::new(server_cfg);

        client.connect(addr(SERVER), Instant::now());
        pump(&mut client, &mut server);

        let payload = vec![0u8; 200];
        assert!(client.enqueue_data(&addr(SERVER), &payload));
        pump(&mut client, &mut server);
        assert!(server.take_events().iter().any(|e| matches!(
            e,
            SocketEvent::DataReceived { remote, data }
                if *remote == addr(CLIENT) && data.as_ref() == payload.as_slice()
        )));
    }

    #[test]
    fn terminate_notifies_remote_and_removes_session() {
        let now = Instant::now();
        let mut client = SoeMultiplexer::new(config("TestProtocol", 1));
        let mut server = SoeMultiplexer::new(config("TestProtocol", 2));

        client.connect(addr(SERVER), now);
        pump(&mut client, &mut server);
        // Drain the opened events.
        client.take_events();
        server.take_events();

        client.terminate(&addr(SERVER), DisconnectReason::Application, now);
        pump(&mut client, &mut server);

        assert_eq!(client.session_count(), 0);
        assert_eq!(server.session_count(), 0);
        assert!(server.take_events().iter().any(|e| matches!(
            e,
            SocketEvent::SessionClosed { remote, reason }
                if *remote == addr(CLIENT) && *reason == DisconnectReason::Application
        )));
    }

    #[test]
    fn ignores_stray_datagram_without_session() {
        let now = Instant::now();
        let mut server = SoeMultiplexer::<SocketAddr>::new(config("TestProtocol", 1));

        // A contextual-looking datagram from an unknown peer is dropped, not turned
        // into a session.
        server.process_incoming(addr(CLIENT), Bytes::from_static(&[0x00, 0x09, 0x00]), now);

        assert_eq!(server.session_count(), 0);
        assert!(server.take_outgoing().is_empty());
        assert!(server.take_events().is_empty());
    }

    #[test]
    fn remaps_port_for_matching_session() {
        let now = Instant::now();
        let mut client = SoeMultiplexer::new(config("TestProtocol", 1));
        let mut server_cfg = config("TestProtocol", 2);
        server_cfg.allow_port_remaps = true;
        let mut server = SoeMultiplexer::new(server_cfg);

        client.connect(addr(SERVER), now);
        pump(&mut client, &mut server);

        let session = server.session(&addr(CLIENT)).expect("server session");
        let remap = RemapConnection {
            session_id: session.session_id(),
            crc_seed: session.crc_seed(),
        };
        let mut buf = [0u8; RemapConnection::SIZE];
        let n = remap.serialize(&mut buf).unwrap();

        let new_client = addr("127.0.0.1:4099");
        server.process_incoming(new_client, Bytes::copy_from_slice(&buf[..n]), now);

        assert!(server.session(&addr(CLIENT)).is_none());
        assert!(server.session(&new_client).is_some());
    }

    #[test]
    fn rejects_remap_from_different_host() {
        let now = Instant::now();
        let mut client = SoeMultiplexer::new(config("TestProtocol", 1));
        let mut server_cfg = config("TestProtocol", 2);
        server_cfg.allow_port_remaps = true;
        let mut server = SoeMultiplexer::new(server_cfg);

        client.connect(addr(SERVER), now);
        pump(&mut client, &mut server);

        let session = server.session(&addr(CLIENT)).expect("server session");
        let remap = RemapConnection {
            session_id: session.session_id(),
            crc_seed: session.crc_seed(),
        };
        let mut buf = [0u8; RemapConnection::SIZE];
        let n = remap.serialize(&mut buf).unwrap();

        // A remap arriving from a different host (not just a different port) must be
        // refused as a likely hijack attempt.
        let attacker = addr("10.0.0.1:5000");
        server.process_incoming(attacker, Bytes::copy_from_slice(&buf[..n]), now);

        assert!(server.session(&addr(CLIENT)).is_some());
        assert!(server.session(&attacker).is_none());
    }
}
