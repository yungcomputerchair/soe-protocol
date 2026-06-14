//! The reliable data output channel: converts application data into ordered,
//! fragmented reliable data packets, and resends them until acknowledged.
//!
//! This is a port of the reference implementation's simplified
//! `ReliableDataOutputChannel2`, which trades the original's multi-packet bundling
//! for a much simpler (and less bug-prone) go-back-N style window.
//!
//! Like the input channel, this is a sans-I/O component: enqueued data is fragmented
//! into outgoing packets which accumulate in an internal queue. Calling
//! [`ReliableDataOutputChannel::run_tick`] moves due packets into the outgoing buffer
//! (drained via [`ReliableDataOutputChannel::take_outgoing`]). Acknowledgements are
//! fed back in via [`ReliableDataOutputChannel::notify_of_acknowledge`] /
//! [`ReliableDataOutputChannel::notify_of_acknowledge_all`]. Time is supplied by the
//! caller as [`Instant`] values.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use crate::protocol::OpCode;
use crate::rc4::Rc4KeyState;

use super::true_incoming_sequence;

/// The size of a reliable data packet's sequence prefix.
const SEQUENCE_SIZE: usize = 2;
/// The size of a master fragment's total-length prefix.
const FRAGMENT_LENGTH_SIZE: usize = 4;

/// Statistics gathered while sending reliable data.
#[derive(Debug, Default, Clone)]
pub struct DataOutputStats {
    /// Total reliable data packets dispatched, including re-sends.
    pub total_sent: u64,
    /// Total reliable data packets that were re-sent.
    pub total_resent: u64,
    /// Total acknowledgement packets received (including ack-alls).
    pub incoming_acknowledge_count: u64,
    /// Total reliable data packets acknowledged (including via ack-all).
    pub actual_acknowledge_count: u64,
}

/// Configuration controlling the output channel's behaviour.
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// The maximum length, in bytes, of the data portion (sequence + data) of a
    /// single reliable data packet. This is the remote UDP length minus the OP code
    /// and CRC.
    pub max_data_length: usize,
    /// The maximum number of unacknowledged reliable data packets that may be in
    /// flight at once (the send window).
    pub max_queued_outgoing: usize,
    /// How long to wait for an acknowledgement before resending from the start of
    /// the window.
    pub ack_wait: Duration,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            max_data_length: 508,
            max_queued_outgoing: 196,
            ack_wait: Duration::from_millis(500),
        }
    }
}

/// A reliable data packet the channel wishes to send (without OP code or CRC
/// framing, which the session layer applies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingReliable {
    /// The OP code of the packet ([`OpCode::ReliableData`] or
    /// [`OpCode::ReliableDataFragment`]).
    pub op_code: OpCode,
    /// The packet payload: a big-endian `u16` sequence, an optional big-endian `u32`
    /// total-length prefix (master fragments only), and the data chunk.
    pub payload: Bytes,
}

#[derive(Debug)]
struct StashedOutputPacket {
    is_fragment: bool,
    data: Bytes,
    sent: bool,
}

/// Converts application data into ordered, fragmented reliable data packets.
#[derive(Debug)]
pub struct ReliableDataOutputChannel {
    config: OutputConfig,
    cipher: Option<Rc4KeyState>,

    dispatch_queue: VecDeque<(i64, StashedOutputPacket)>,

    /// The total number of sequences that have been output.
    total_sequence: i64,
    /// The maximum sequence number that the client is known to have received.
    max_client_sequence: i64,
    /// The index into `dispatch_queue` of the next packet to dispatch.
    current_dispatch_index: usize,

    last_ack_at: Instant,

    outgoing: Vec<OutgoingReliable>,
    stats: DataOutputStats,
}

impl ReliableDataOutputChannel {
    /// Creates a new output channel. `cipher` is the initial RC4 key state; pass
    /// `Some(..)` to enable RC4 encryption of the proxied application data, or `None`
    /// to pass it through unencrypted.
    pub fn new(config: OutputConfig, cipher: Option<Rc4KeyState>, now: Instant) -> Self {
        Self {
            config,
            cipher,
            dispatch_queue: VecDeque::new(),
            total_sequence: 0,
            max_client_sequence: 0,
            current_dispatch_index: 0,
            last_ack_at: now,
            outgoing: Vec::new(),
            stats: DataOutputStats::default(),
        }
    }

    /// Returns the gathered output statistics.
    pub fn stats(&self) -> &DataOutputStats {
        &self.stats
    }

    /// Drains the outgoing reliable data packets accumulated so far.
    pub fn take_outgoing(&mut self) -> Vec<OutgoingReliable> {
        std::mem::take(&mut self.outgoing)
    }

    /// Returns the number of reliable data packets currently awaiting acknowledgement.
    pub fn queued_len(&self) -> usize {
        self.dispatch_queue.len()
    }

    /// Sets the maximum length of the data portion (sequence + data) of a single
    /// packet. Should not be called after data has been enqueued.
    pub fn set_max_data_length(&mut self, max_data_length: usize) {
        self.config.max_data_length = max_data_length;
    }

    fn max_chunk(&self) -> usize {
        self.config.max_data_length - SEQUENCE_SIZE
    }

    /// Enqueues application data to be sent on the reliable channel. The data is
    /// fragmented as required to fit within the configured maximum packet length.
    pub fn enqueue_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut remaining: Bytes = match &mut self.cipher {
            Some(_) => self.encrypt(data),
            None => Bytes::copy_from_slice(data),
        };

        let is_fragment = remaining.len() > self.max_chunk();
        self.stash_fragment(&mut remaining, true, is_fragment);
        while !remaining.is_empty() {
            self.stash_fragment(&mut remaining, false, true);
        }
    }

    /// Runs a tick of the output channel, moving due packets into the outgoing
    /// buffer. If no acknowledgement has been received within the configured
    /// `ack_wait`, dispatch restarts from the front of the window.
    pub fn run_tick(&mut self, now: Instant) {
        if now.duration_since(self.last_ack_at) > self.config.ack_wait {
            self.current_dispatch_index = 0;
        }

        let max_index = self
            .dispatch_queue
            .len()
            .min(self.config.max_queued_outgoing + self.current_dispatch_index);

        while self.current_dispatch_index < max_index {
            let (_, packet) = &mut self.dispatch_queue[self.current_dispatch_index];
            let op_code = if packet.is_fragment {
                OpCode::ReliableDataFragment
            } else {
                OpCode::ReliableData
            };

            self.stats.total_sent += 1;
            if packet.sent {
                self.stats.total_resent += 1;
            }
            packet.sent = true;

            let payload = packet.data.clone();
            self.outgoing.push(OutgoingReliable { op_code, payload });
            self.current_dispatch_index += 1;
        }
    }

    /// Notifies the channel that the remote has acknowledged a single sequence.
    pub fn notify_of_acknowledge(&mut self, sequence: u16, now: Instant) {
        let seq = self.true_incoming(sequence);
        self.stats.incoming_acknowledge_count += 1;

        if let Some(pos) = self.dispatch_queue.iter().position(|(s, _)| *s == seq) {
            self.dispatch_queue.remove(pos);
            self.current_dispatch_index = self.current_dispatch_index.saturating_sub(1);
            self.stats.actual_acknowledge_count += 1;
        }

        if seq > self.max_client_sequence {
            self.max_client_sequence = seq;
        }
        self.last_ack_at = now;
    }

    /// Notifies the channel that the remote has acknowledged all sequences up to and
    /// including the given one.
    pub fn notify_of_acknowledge_all(&mut self, sequence: u16, now: Instant) {
        let seq = self.true_incoming(sequence);
        self.stats.incoming_acknowledge_count += 1;

        while let Some((s, _)) = self.dispatch_queue.front() {
            if *s > seq {
                break;
            }
            self.dispatch_queue.pop_front();
            self.current_dispatch_index = self.current_dispatch_index.saturating_sub(1);
            self.stats.actual_acknowledge_count += 1;
        }

        if seq > self.max_client_sequence {
            self.max_client_sequence = seq;
        }
        self.last_ack_at = now;
    }

    fn stash_fragment(&mut self, data: &mut Bytes, is_master: bool, is_fragment: bool) {
        let mut amount = data.len().min(self.max_chunk());

        let mut buf = BytesMut::with_capacity(SEQUENCE_SIZE + FRAGMENT_LENGTH_SIZE + amount);
        buf.put_u16(self.total_sequence as u16);

        if is_master && is_fragment {
            buf.put_u32(data.len() as u32);
            amount -= FRAGMENT_LENGTH_SIZE;
        }

        buf.extend_from_slice(&data[..amount]);

        self.dispatch_queue.push_back((
            self.total_sequence,
            StashedOutputPacket {
                is_fragment,
                data: buf.freeze(),
                sent: false,
            },
        ));

        self.total_sequence += 1;
        *data = data.slice(amount..);
    }

    /// Encrypts `data` with the channel's RC4 cipher. A leading zero byte is
    /// prepended when the ciphertext itself begins with a zero, mirroring the input
    /// channel's padding-strip logic.
    fn encrypt(&mut self, data: &[u8]) -> Bytes {
        let cipher = self
            .cipher
            .as_mut()
            .expect("encrypt called without a cipher");

        let mut buf = BytesMut::with_capacity(data.len() + 1);
        buf.put_u8(0);
        buf.extend_from_slice(data);
        cipher.transform_in_place(&mut buf[1..]);

        let frozen = buf.freeze();
        if frozen[1] == 0 {
            frozen
        } else {
            frozen.slice(1..)
        }
    }

    fn true_incoming(&self, packet_sequence: u16) -> i64 {
        true_incoming_sequence(
            packet_sequence,
            self.max_client_sequence,
            self.config.max_queued_outgoing as i64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_DATA_LENGTH: usize = 506; // 512 (udp) - 2 (op) - 2 (seq) - 2 (crc)
    const FRAGMENT_WINDOW_SIZE: usize = 8;

    struct Clock {
        now: Instant,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }
        fn advance(&mut self, by: Duration) -> Instant {
            self.now += by;
            self.now
        }
    }

    fn new_channel(clock: &Clock) -> ReliableDataOutputChannel {
        let config = OutputConfig {
            max_data_length: MAX_DATA_LENGTH + SEQUENCE_SIZE,
            max_queued_outgoing: FRAGMENT_WINDOW_SIZE,
            ack_wait: Duration::from_millis(500),
        };
        ReliableDataOutputChannel::new(config, None, clock.now)
    }

    /// A deterministic pseudo-random byte buffer.
    fn generate_packet(size: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678 ^ size as u32;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    /// Asserts that the data carried by `packets` (stripping the sequence and, for
    /// the first packet if `expect_master_fragment`, the length prefix) concatenates
    /// to exactly `buffer`.
    fn assert_packets_equal_buffer(
        packets: &[OutgoingReliable],
        buffer: &[u8],
        mut expect_master_fragment: bool,
    ) {
        let mut position = 0;
        for packet in packets {
            let data_offset = SEQUENCE_SIZE
                + if expect_master_fragment {
                    FRAGMENT_LENGTH_SIZE
                } else {
                    0
                };
            expect_master_fragment = false;

            let data = &packet.payload[data_offset..];
            assert!(
                position + data.len() <= buffer.len(),
                "received more data than expected"
            );
            assert_eq!(&buffer[position..position + data.len()], data);
            position += data.len();
        }
        assert_eq!(position, buffer.len(), "did not receive the whole buffer");
    }

    #[test]
    fn repeats_data_on_ack_failure() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let fragment_count = 4;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);

        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet, true);

        // Don't acknowledge; after the ack wait elapses the data is resent in full.
        ch.run_tick(clock.advance(Duration::from_millis(600)));
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet, true);
    }

    #[test]
    fn repeats_data_from_arbitrary_position_on_ack_delay() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let fragment_count = 4;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);

        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet, true);

        ch.notify_of_acknowledge_all(1, clock.advance(Duration::from_millis(1)));

        ch.run_tick(clock.advance(Duration::from_millis(600)));
        // The master fragment (MAX-4) and the next fragment (MAX) were acknowledged.
        let expected_consumed = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH;
        assert_packets_equal_buffer(&ch.take_outgoing(), &packet[expected_consumed..], false);
    }

    #[test]
    fn repeats_full_window_from_arbitrary_position_on_ack_delay() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let fragment_count = FRAGMENT_WINDOW_SIZE * 2;
        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (fragment_count - 1);
        let packet = generate_packet(packet_length);

        ch.enqueue_data(&packet);
        ch.run_tick(clock.advance(Duration::from_millis(1)));

        // Only a full window of packets is sent initially.
        let expected_receive_length =
            MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (FRAGMENT_WINDOW_SIZE - 1);
        assert_packets_equal_buffer(
            &ch.take_outgoing(),
            &packet[..expected_receive_length],
            true,
        );

        ch.notify_of_acknowledge_all(
            (FRAGMENT_WINDOW_SIZE - 2) as u16,
            clock.advance(Duration::from_millis(1)),
        );
        ch.run_tick(clock.advance(Duration::from_millis(600)));

        let expected_consumed = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * (FRAGMENT_WINDOW_SIZE - 2);
        let expected_repeat_length = MAX_DATA_LENGTH * FRAGMENT_WINDOW_SIZE;
        assert_packets_equal_buffer(
            &ch.take_outgoing(),
            &packet[expected_consumed..expected_consumed + expected_repeat_length],
            false,
        );
    }

    #[test]
    fn single_small_packet_is_not_fragmented() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let data = generate_packet(32);
        ch.enqueue_data(&data);
        ch.run_tick(clock.advance(Duration::from_millis(1)));

        let outgoing = ch.take_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].op_code, OpCode::ReliableData);
        // No length prefix: payload is [seq u16][data].
        assert_eq!(&outgoing[0].payload[SEQUENCE_SIZE..], &data[..]);
    }

    #[test]
    fn single_ack_removes_specific_packet() {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock);

        let packet_length = MAX_DATA_LENGTH - 4 + MAX_DATA_LENGTH * 3;
        let packet = generate_packet(packet_length);
        ch.enqueue_data(&packet);
        assert_eq!(ch.queued_len(), 4);

        ch.run_tick(clock.advance(Duration::from_millis(1)));
        let _ = ch.take_outgoing();

        ch.notify_of_acknowledge(2, clock.advance(Duration::from_millis(1)));
        assert_eq!(ch.queued_len(), 3);
        assert_eq!(ch.stats().actual_acknowledge_count, 1);
    }
}
