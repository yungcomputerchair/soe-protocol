//! The reliable data input channel: validates, orders and reassembles incoming
//! reliable data, decrypts/unbundles it, and emits acknowledgements.
//!
//! This is a sans-I/O component. Incoming packets are fed via
//! [`ReliableDataInputChannel::handle_reliable_data`] /
//! [`ReliableDataInputChannel::handle_reliable_data_fragment`], and the channel
//! accumulates outgoing acknowledgement packets (drained via
//! [`ReliableDataInputChannel::take_outgoing`]) and decoded application data
//! (drained via [`ReliableDataInputChannel::take_app_data`]). Time is supplied by
//! the caller as [`Instant`] values.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use crate::constants::MULTI_DATA_INDICATOR;
use crate::io::BinaryReader;
use crate::protocol::OpCode;
use crate::rc4::Rc4KeyState;
use crate::varint::data_bundle;

use super::true_incoming_sequence;

/// Statistics gathered while receiving reliable data.
#[derive(Debug, Default, Clone)]
pub struct DataInputStats {
    /// Total reliable data packets received, including duplicates.
    pub total_received: u64,
    /// Number of duplicate reliable data packets received.
    pub duplicate_count: u64,
    /// Number of reliable data packets received out of order.
    pub out_of_order_count: u64,
    /// Total application bytes received (excluding indicators/padding).
    pub total_received_bytes: u64,
    /// Number of acknowledgement packets emitted.
    pub acknowledge_count: u64,
}

/// Configuration controlling the input channel's behaviour.
#[derive(Debug, Clone)]
pub struct InputConfig {
    /// Maximum number of incoming reliable data packets that may be stashed.
    pub max_queued_incoming: u16,
    /// Whether every data packet is acknowledged individually.
    pub acknowledge_all_data: bool,
    /// The acknowledgement window used to decide when to send an `AcknowledgeAll`.
    pub data_ack_window: u16,
    /// Maximum delay before acknowledging incoming reliable data sequences.
    pub max_ack_delay: Duration,
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            max_queued_incoming: 256,
            acknowledge_all_data: false,
            data_ack_window: 32,
            max_ack_delay: Duration::from_millis(2),
        }
    }
}

/// A contextual packet the channel wishes to send (without OP code or CRC framing,
/// which the session layer applies). For this channel it is always an acknowledgement
/// carrying a single sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutgoingContextual {
    /// The OP code of the packet ([`OpCode::Acknowledge`] or [`OpCode::AcknowledgeAll`]).
    pub op_code: OpCode,
    /// The acknowledged sequence number.
    pub sequence: u16,
}

struct Stashed {
    data: Bytes,
    is_fragment: bool,
}

/// Handles reliable data packets, extracting the proxied application data in order.
pub struct ReliableDataInputChannel {
    config: InputConfig,
    cipher: Option<Rc4KeyState>,

    /// The next reliable data sequence we expect to receive.
    window_start_sequence: i64,

    /// Buffer accumulating fragments of the current data unit.
    current_buffer: Option<BytesMut>,
    /// The expected total length of the current data unit.
    expected_data_length: usize,

    /// The last sequence we acknowledged via `AcknowledgeAll`.
    last_ack_all_sequence: i64,
    last_ack_all_time: Instant,

    stash: Vec<Option<Stashed>>,
    stats: DataInputStats,

    outgoing: Vec<OutgoingContextual>,
    app_data: Vec<Bytes>,
}

impl ReliableDataInputChannel {
    /// Creates a new input channel. `cipher` is the initial RC4 key state; pass
    /// `Some(..)` to enable RC4 decryption of the proxied application data, or
    /// `None` to pass it through unencrypted.
    pub fn new(config: InputConfig, cipher: Option<Rc4KeyState>, now: Instant) -> Self {
        let capacity = config.max_queued_incoming as usize;
        let stash = std::iter::repeat_with(|| None).take(capacity).collect();

        Self {
            config,
            cipher,
            window_start_sequence: 0,
            current_buffer: None,
            expected_data_length: 0,
            last_ack_all_sequence: -1,
            last_ack_all_time: now,
            stash,
            stats: DataInputStats::default(),
            outgoing: Vec::new(),
            app_data: Vec::new(),
        }
    }

    /// Returns the gathered input statistics.
    pub fn stats(&self) -> &DataInputStats {
        &self.stats
    }

    /// Drains the outgoing acknowledgement packets accumulated so far.
    pub fn take_outgoing(&mut self) -> Vec<OutgoingContextual> {
        std::mem::take(&mut self.outgoing)
    }

    /// Drains the decoded application data buffers accumulated so far.
    pub fn take_app_data(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.app_data)
    }

    fn max_queued(&self) -> i64 {
        self.config.max_queued_incoming as i64
    }

    /// Runs periodic channel logic: emits a buffered `AcknowledgeAll` when due.
    pub fn run_tick(&mut self, now: Instant) {
        let to_ack = self.window_start_sequence - 1;

        // No need to ack-all if acking everything individually, or we've already
        // acked up to the current window start.
        if self.config.acknowledge_all_data || to_ack <= self.last_ack_all_sequence {
            return;
        }

        let need_ack = now.duration_since(self.last_ack_all_time) > self.config.max_ack_delay
            || to_ack >= self.last_ack_all_sequence + (self.config.data_ack_window / 2) as i64;

        if need_ack {
            self.send_ack_all(to_ack, now);
        }
    }

    /// Handles a [`OpCode::ReliableData`] packet (OP code already stripped).
    pub fn handle_reliable_data(&mut self, data: Bytes, now: Instant) {
        if !self.preprocess(&data, false, now) {
            return;
        }
        self.process_data(data.slice(2..));
        self.window_start_sequence += 1;
        self.consume_stashed();
    }

    /// Handles a [`OpCode::ReliableDataFragment`] packet (OP code already stripped).
    pub fn handle_reliable_data_fragment(&mut self, data: Bytes, now: Instant) {
        if !self.preprocess(&data, true, now) {
            return;
        }
        self.write_immediate_fragment(&data[2..]);
        self.window_start_sequence += 1;
        self.try_process_current_buffer();
        self.consume_stashed();
    }

    fn emit(&mut self, op_code: OpCode, sequence: u16) {
        self.outgoing.push(OutgoingContextual { op_code, sequence });
    }

    fn send_ack_all(&mut self, sequence: i64, now: Instant) {
        self.emit(OpCode::AcknowledgeAll, sequence as u16);
        self.stats.acknowledge_count += 1;
        self.last_ack_all_sequence = sequence;
        self.last_ack_all_time = now;
    }

    /// Validates and, if necessary, stashes incoming reliable data. Returns `true`
    /// if the data (with its sequence stripped) should be processed immediately.
    fn preprocess(&mut self, data: &Bytes, is_fragment: bool, now: Instant) -> bool {
        self.stats.total_received += 1;

        let (sequence, packet_sequence) = match self.is_valid_reliable_data(data, now) {
            Some(v) => v,
            None => return false,
        };

        let ahead = sequence != self.window_start_sequence;

        // Ack now if in ack-all mode or this is ahead of our expectations.
        if self.config.acknowledge_all_data || ahead {
            self.emit(OpCode::Acknowledge, packet_sequence);
        }

        if !ahead {
            return true;
        }

        // Out of order: stash it.
        self.stats.out_of_order_count += 1;
        let spot = sequence.rem_euclid(self.max_queued()) as usize;
        if self.stash[spot].is_some() {
            self.stats.duplicate_count += 1;
            return false;
        }

        self.stash[spot] = Some(Stashed {
            data: data.slice(2..),
            is_fragment,
        });
        false
    }

    /// Checks whether the given data is within the current window. Returns the true
    /// sequence and embedded packet sequence if it should be processed/stashed.
    fn is_valid_reliable_data(&mut self, data: &[u8], now: Instant) -> Option<(i64, u16)> {
        if data.len() < 2 {
            return None;
        }
        let packet_sequence = u16::from_be_bytes([data[0], data[1]]);
        let sequence = true_incoming_sequence(
            packet_sequence,
            self.window_start_sequence,
            self.max_queued(),
        );

        // Too far ahead of our window; drop it.
        if sequence > self.window_start_sequence + self.max_queued() {
            return None;
        }

        // Inside the window.
        if sequence >= self.window_start_sequence {
            return Some((sequence, packet_sequence));
        }

        // Already processed: nudge the remote, but not too frequently.
        if now.duration_since(self.last_ack_all_time) < self.config.max_ack_delay {
            self.send_ack_all(self.window_start_sequence - 1, now);
        }
        self.stats.duplicate_count += 1;
        None
    }

    /// Appends fragment data to the current buffer, allocating it (and reading the
    /// total length prefix) if this is the master fragment.
    fn write_immediate_fragment(&mut self, data: &[u8]) {
        if let Some(buf) = &mut self.current_buffer {
            buf.extend_from_slice(data);
        } else {
            let expected = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            self.expected_data_length = expected;
            let mut buf = BytesMut::with_capacity(expected);
            buf.extend_from_slice(&data[4..]);
            self.current_buffer = Some(buf);
        }
    }

    fn try_process_current_buffer(&mut self) {
        let ready =
            matches!(&self.current_buffer, Some(buf) if buf.len() >= self.expected_data_length);
        if !ready {
            return;
        }
        let buf = self.current_buffer.take().unwrap();
        self.process_data(buf.freeze());
        self.expected_data_length = 0;
    }

    fn consume_stashed(&mut self) {
        loop {
            let spot = self.window_start_sequence.rem_euclid(self.max_queued()) as usize;
            let Some(item) = self.stash[spot].take() else {
                break;
            };

            if item.is_fragment {
                self.write_immediate_fragment(&item.data);
                self.try_process_current_buffer();
            } else {
                self.process_data(item.data);
            }

            self.window_start_sequence += 1;
        }
    }

    fn process_data(&mut self, data: Bytes) {
        if data.len() > 2 && data[0..2] == MULTI_DATA_INDICATOR {
            let mut reader = BinaryReader::new(&data);
            // Skip the multi-data indicator.
            if reader.skip(2).is_err() {
                return;
            }
            while reader.remaining() > 0 {
                let len = match data_bundle::read(&mut reader) {
                    Ok(l) => l as usize,
                    Err(_) => break,
                };
                let start = reader.offset();
                if reader.skip(len).is_err() {
                    break;
                }
                let chunk = data.slice(start..start + len);
                self.decrypt_and_handle(chunk);
            }
        } else {
            self.decrypt_and_handle(data);
        }
    }

    fn decrypt_and_handle(&mut self, data: Bytes) {
        let processed = match &mut self.cipher {
            Some(cipher) => {
                // A single leading 0x00 byte may pad encrypted data; ignore it.
                let d = if data.len() > 1 && data[0] == 0 {
                    data.slice(1..)
                } else {
                    data
                };
                let mut buf = BytesMut::from(&d[..]);
                cipher.transform_in_place(&mut buf);
                buf.freeze()
            }
            None => data,
        };

        self.stats.total_received_bytes += processed.len() as u64;
        self.app_data.push(processed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A monotonic test clock that advances by 1ms on each read, so that
    /// zero-delay ack logic fires deterministically.
    struct Clock {
        now: Instant,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }
        fn tick(&mut self) -> Instant {
            self.now += Duration::from_millis(1);
            self.now
        }
    }

    fn config(acknowledge_all_data: bool) -> InputConfig {
        InputConfig {
            acknowledge_all_data,
            max_ack_delay: Duration::ZERO,
            ..InputConfig::default()
        }
    }

    /// Builds a reliable data/fragment packet body (sequence + optional complete
    /// length + data), returning (packet, data).
    fn data_fragment(
        sequence: u16,
        complete_len: Option<u32>,
        data_len: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let data: Vec<u8> = (0..data_len)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(sequence as u8))
            .collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&sequence.to_be_bytes());
        if let Some(cl) = complete_len {
            buf.extend_from_slice(&cl.to_be_bytes());
        }
        buf.extend_from_slice(&data);
        (buf, data)
    }

    /// Runs a tick, collects any newly-emitted acks into `pending`, then asserts the
    /// front of `pending` matches the expected op/seq and pops it.
    fn assert_pop_ack(
        ch: &mut ReliableDataInputChannel,
        clock: &mut Clock,
        pending: &mut Vec<OutgoingContextual>,
        expected_sequence: u16,
        expect_all: bool,
    ) {
        ch.run_tick(clock.tick());
        pending.extend(ch.take_outgoing());
        assert!(!pending.is_empty(), "expected an ack to be pending");
        let ack = pending.remove(0);
        let expected_op = if expect_all {
            OpCode::AcknowledgeAll
        } else {
            OpCode::Acknowledge
        };
        assert_eq!(ack.op_code, expected_op);
        assert_eq!(ack.sequence, expected_sequence);
    }

    const DATA_LENGTH: usize = 16;

    fn new_channel(clock: &Clock, ack_all: bool) -> ReliableDataInputChannel {
        ReliableDataInputChannel::new(config(ack_all), None, clock.now)
    }

    fn run_sequential_fragment_insert(ack_all: bool) {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock, ack_all);
        let mut pending: Vec<OutgoingContextual> = Vec::new();

        let (f0, d0) = data_fragment(0, Some((DATA_LENGTH * 3) as u32), DATA_LENGTH);
        let (f1, d1) = data_fragment(1, None, DATA_LENGTH);
        let (f2, d2) = data_fragment(2, None, DATA_LENGTH);

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f0), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 0, !ack_all);
        assert!(ch.take_app_data().is_empty());

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f1), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 1, !ack_all);
        assert!(ch.take_app_data().is_empty());

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f2), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 2, !ack_all);
        let app = ch.take_app_data();
        assert_eq!(app.len(), 1);

        let stitched = &app[0];
        assert_eq!(&stitched[0..DATA_LENGTH], &d0[..]);
        assert_eq!(&stitched[DATA_LENGTH..DATA_LENGTH * 2], &d1[..]);
        assert_eq!(&stitched[DATA_LENGTH * 2..], &d2[..]);
        assert!(pending.is_empty(), "no superfluous acks");
    }

    #[test]
    fn sequential_fragment_insert() {
        run_sequential_fragment_insert(true);
        run_sequential_fragment_insert(false);
    }

    fn run_non_sequential_fragment_insert(ack_all: bool) {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock, ack_all);
        let mut pending: Vec<OutgoingContextual> = Vec::new();

        let (f0, d0) = data_fragment(0, Some((DATA_LENGTH * 3) as u32), DATA_LENGTH);
        let (f1, d1) = data_fragment(1, None, DATA_LENGTH);
        let (f2, d2) = data_fragment(2, None, DATA_LENGTH);

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f2), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 2, false);

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f0), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 0, !ack_all);
        assert!(ch.take_app_data().is_empty());

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f1), clock.tick());
        assert_pop_ack(
            &mut ch,
            &mut clock,
            &mut pending,
            if ack_all { 1 } else { 2 },
            !ack_all,
        );
        let app = ch.take_app_data();
        assert_eq!(app.len(), 1);

        let stitched = &app[0];
        assert_eq!(&stitched[0..DATA_LENGTH], &d0[..]);
        assert_eq!(&stitched[DATA_LENGTH..DATA_LENGTH * 2], &d1[..]);
        assert_eq!(&stitched[DATA_LENGTH * 2..], &d2[..]);
        assert!(pending.is_empty(), "no superfluous acks");
    }

    #[test]
    fn non_sequential_fragment_insert() {
        run_non_sequential_fragment_insert(true);
        run_non_sequential_fragment_insert(false);
    }

    fn run_non_fragment_insert(ack_all: bool) {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock, ack_all);
        let mut pending: Vec<OutgoingContextual> = Vec::new();

        let (p0, d0) = data_fragment(0, None, DATA_LENGTH);
        let (p1, d1) = data_fragment(1, None, DATA_LENGTH);
        let (p2, d2) = data_fragment(2, None, DATA_LENGTH);

        ch.handle_reliable_data(Bytes::copy_from_slice(&p0), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 0, !ack_all);
        let app = ch.take_app_data();
        assert_eq!(app, vec![d0]);

        ch.handle_reliable_data(Bytes::copy_from_slice(&p2), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 2, false);

        ch.handle_reliable_data(Bytes::copy_from_slice(&p1), clock.tick());
        assert_pop_ack(
            &mut ch,
            &mut clock,
            &mut pending,
            if ack_all { 1 } else { 2 },
            !ack_all,
        );
        let app = ch.take_app_data();
        assert_eq!(app, vec![d1, d2]);
        assert!(pending.is_empty(), "no superfluous acks");
    }

    #[test]
    fn non_fragment_insert() {
        run_non_fragment_insert(true);
        run_non_fragment_insert(false);
    }

    fn run_fragmented_insert_of_two_datas(ack_all: bool) {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock, ack_all);
        let mut pending: Vec<OutgoingContextual> = Vec::new();

        let (f0, d0) = data_fragment(0, Some((DATA_LENGTH * 2) as u32), DATA_LENGTH);
        let (f1, d1) = data_fragment(1, None, DATA_LENGTH);
        let (f2, d2) = data_fragment(2, Some((DATA_LENGTH * 2) as u32), DATA_LENGTH);
        let (f3, d3) = data_fragment(3, None, DATA_LENGTH);

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f0), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 0, !ack_all);
        assert!(ch.take_app_data().is_empty());

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f1), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 1, !ack_all);
        let app = ch.take_app_data();
        assert_eq!(app.len(), 1);
        assert_eq!(&app[0][..DATA_LENGTH], &d0[..]);
        assert_eq!(&app[0][DATA_LENGTH..], &d1[..]);

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f3), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 3, false);
        assert!(ch.take_app_data().is_empty());

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f2), clock.tick());
        assert_pop_ack(
            &mut ch,
            &mut clock,
            &mut pending,
            if ack_all { 2 } else { 3 },
            !ack_all,
        );
        let app = ch.take_app_data();
        assert_eq!(app.len(), 1);
        assert_eq!(&app[0][..DATA_LENGTH], &d2[..]);
        assert_eq!(&app[0][DATA_LENGTH..], &d3[..]);
    }

    #[test]
    fn fragmented_insert_of_two_datas() {
        run_fragmented_insert_of_two_datas(true);
        run_fragmented_insert_of_two_datas(false);
    }

    fn run_sequence_waiting_on_data(ack_all: bool) {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock, ack_all);
        let mut pending: Vec<OutgoingContextual> = Vec::new();

        let (p0, d0) = data_fragment(0, None, DATA_LENGTH);
        let (f1, d1) = data_fragment(1, Some((DATA_LENGTH * 2) as u32), DATA_LENGTH);
        let (f2, d2) = data_fragment(2, None, DATA_LENGTH);

        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f1), clock.tick());
        ch.handle_reliable_data_fragment(Bytes::copy_from_slice(&f2), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 1, false);
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 2, false);

        ch.handle_reliable_data(Bytes::copy_from_slice(&p0), clock.tick());
        assert_pop_ack(
            &mut ch,
            &mut clock,
            &mut pending,
            if ack_all { 0 } else { 2 },
            !ack_all,
        );

        let app = ch.take_app_data();
        assert_eq!(app.len(), 2);
        assert_eq!(app[0], d0);
        assert_eq!(&app[1][..DATA_LENGTH], &d1[..]);
        assert_eq!(&app[1][DATA_LENGTH..], &d2[..]);
    }

    #[test]
    fn sequence_waiting_on_data() {
        run_sequence_waiting_on_data(true);
        run_sequence_waiting_on_data(false);
    }

    fn run_multi_data(ack_all: bool) {
        let mut clock = Clock::new();
        let mut ch = new_channel(&clock, ack_all);
        let mut pending: Vec<OutgoingContextual> = Vec::new();

        // [seq u16][00 19][len=1][2][len=1][4]. A data-bundle length of 1 encodes
        // as a single 0x01 byte.
        let mut multi = vec![0u8, 0]; // sequence 0
        multi.extend_from_slice(&MULTI_DATA_INDICATOR);
        multi.extend_from_slice(&[1, 2]); // length 1, data byte 2
        multi.extend_from_slice(&[1, 4]); // length 1, data byte 4

        ch.handle_reliable_data(Bytes::copy_from_slice(&multi), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 0, !ack_all);
        assert_eq!(ch.take_app_data(), vec![vec![2u8], vec![4u8]]);

        multi[1] = 0x01; // increment sequence to 1
        ch.handle_reliable_data(Bytes::copy_from_slice(&multi), clock.tick());
        assert_pop_ack(&mut ch, &mut clock, &mut pending, 1, !ack_all);
        assert_eq!(ch.take_app_data(), vec![vec![2u8], vec![4u8]]);
    }

    #[test]
    fn multi_data() {
        run_multi_data(true);
        run_multi_data(false);
    }

    /// Regression test for the long-connection sequence-wraparound bug: once the
    /// window advances past the 16-bit boundary, the ack-all throttle must keep
    /// working. Previously `last_ack_all_sequence` stored only the truncated 16-bit
    /// wire value while `to_ack` was the full sequence, so after wraparound the two
    /// could never compare equal and the channel emitted a redundant `AcknowledgeAll`
    /// on every single tick for the rest of the connection.
    #[test]
    fn ack_all_throttled_after_sequence_wraparound() {
        let mut clock = Clock::new();
        // Not ack-all-per-packet mode, so ack-alls come from run_tick.
        let mut ch = new_channel(&clock, false);

        // Feed enough in-order reliable packets to push the window past 2^16.
        let total: u32 = 65_540;
        for i in 0..total {
            let (pkt, _) = data_fragment((i & 0xFFFF) as u16, None, DATA_LENGTH);
            ch.handle_reliable_data(Bytes::copy_from_slice(&pkt), clock.tick());
            // Drop accumulated acks/app-data to keep memory bounded.
            ch.take_outgoing();
            ch.take_app_data();
        }

        // First tick after the data: a single ack-all for the current window is
        // expected (and arms the throttle).
        ch.run_tick(clock.tick());
        let first = ch.take_outgoing();
        assert_eq!(first.len(), 1, "expected exactly one ack-all");
        assert_eq!(first[0].op_code, OpCode::AcknowledgeAll);
        assert_eq!(first[0].sequence, ((total - 1) & 0xFFFF) as u16);

        // No new data has arrived, so subsequent ticks must NOT re-emit an ack-all.
        // (max_ack_delay is ZERO in the test config, so any emission here is the bug.)
        for _ in 0..5 {
            ch.run_tick(clock.tick());
            assert!(
                ch.take_outgoing().is_empty(),
                "ack-all throttle broke after wraparound: redundant ack emitted"
            );
        }
    }
}
