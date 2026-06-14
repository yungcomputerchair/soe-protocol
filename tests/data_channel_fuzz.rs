//! End-to-end fuzz tests for the reliable data channels, ported from the reference
//! implementation's `ReliableDataChannel2EndToEndTests`
//! (`TestAllThePackets` and friends).
//!
//! Each case wires a [`ReliableDataOutputChannel`] directly into a
//! [`ReliableDataInputChannel`] (the "loopback wire"), enqueues a battery of
//! application packets of various sizes, pumps the dispatch/acknowledge cycle to
//! completion, and asserts that the input channel reassembles exactly the same
//! packets, in order. This exercises fragmentation, sequencing, windowing and
//! reassembly together.

use std::time::{Duration, Instant};

use soe_protocol::OpCode;
use soe_protocol::channel::{
    InputConfig, OutputConfig, ReliableDataInputChannel, ReliableDataOutputChannel,
};

/// The maximum length of the data portion (sequence + data) of a single packet:
/// the default UDP length minus the OP code and CRC. Mirrors the output channel's
/// default and the reference test's `MAX_DATA_LENGTH + sizeof(ushort)`.
const MAX_DATA_LENGTH: usize = 508;
/// The fragment window size used by the reference test for both directions.
const WINDOW: usize = 32;

/// Generates a deterministic, reproducible pseudo-random packet of the given size.
///
/// Like the reference test's `GeneratePacket` (which re-seeds `Random` per call),
/// the generator is re-seeded per packet, so every packet shares the same leading
/// bytes. The result is then nudged away from the reserved multi-data indicator
/// prefix, which the input channel would otherwise interpret as a bundle rather
/// than opaque application data.
fn generate_packet(size: usize) -> Vec<u8> {
    let mut state: u64 = 23445;
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        // splitmix64
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(size);
    if size > 2 && out[0] == 0x00 && out[1] == 0x19 {
        out[0] ^= 0xFF;
    }
    out
}

/// Pumps `packets` through a loopback output→input channel pair and asserts they
/// are received intact and in order.
fn assert_roundtrip(packets: &[Vec<u8>]) {
    let start = Instant::now();

    let mut output = ReliableDataOutputChannel::new(
        OutputConfig {
            max_data_length: MAX_DATA_LENGTH,
            max_queued_outgoing: WINDOW,
            ack_wait: Duration::from_millis(500),
        },
        None,
        start,
    );
    let mut input = ReliableDataInputChannel::new(
        InputConfig {
            max_queued_incoming: WINDOW as u16,
            acknowledge_all_data: false,
            data_ack_window: WINDOW as u16,
            max_ack_delay: Duration::ZERO,
        },
        None,
        start,
    );

    for packet in packets {
        output.enqueue_data(packet);
    }

    let mut received: Vec<Vec<u8>> = Vec::new();
    let mut now = start;
    let tick = Duration::from_millis(1);

    // A generous upper bound on iterations: every iteration delivers and acks a full
    // window, so convergence is comfortably within this.
    let total_fragments: usize = packets.iter().map(|p| p.len() / MAX_DATA_LENGTH + 1).sum();
    let max_iters = total_fragments * 4 + 1000;

    let mut iters = 0;
    loop {
        // The tick is far smaller than `ack_wait`, so we never trigger spurious
        // resends; the window advances purely on the acknowledgements we feed back.
        now += tick;

        output.run_tick(now);
        for pkt in output.take_outgoing() {
            match pkt.op_code {
                OpCode::ReliableData => input
                    .handle_reliable_data(pkt.payload, now)
                    .expect("valid reliable data"),
                OpCode::ReliableDataFragment => input
                    .handle_reliable_data_fragment(pkt.payload, now)
                    .expect("valid reliable data fragment"),
                other => panic!("unexpected output op code: {other:?}"),
            }
        }

        for data in input.take_app_data() {
            received.push(data.to_vec());
        }

        input.run_tick(now);
        for ack in input.take_outgoing() {
            match ack.op_code {
                OpCode::Acknowledge => output.notify_of_acknowledge(ack.sequence, now),
                OpCode::AcknowledgeAll => output.notify_of_acknowledge_all(ack.sequence, now),
                other => panic!("unexpected acknowledgement op code: {other:?}"),
            }
        }

        if output.queued_len() == 0 {
            for data in input.take_app_data() {
                received.push(data.to_vec());
            }
            break;
        }

        iters += 1;
        assert!(iters < max_iters, "channels did not converge");
    }

    assert_eq!(
        received.len(),
        packets.len(),
        "received packet count mismatch"
    );
    for (i, (got, expected)) in received.iter().zip(packets).enumerate() {
        assert_eq!(
            got, expected,
            "recomposed packet {i} differs from the original"
        );
    }
}

#[test]
fn single_small_packet() {
    assert_roundtrip(&[generate_packet(5)]);
}

#[test]
fn multiple_small_packets() {
    assert_roundtrip(&[
        generate_packet(3),
        generate_packet(45),
        generate_packet(1),
        generate_packet(214),
    ]);
}

#[test]
fn multiple_small_packets_requiring_fragmentation() {
    assert_roundtrip(&[
        generate_packet(3),
        generate_packet(45),
        generate_packet(1),
        generate_packet(214),
        generate_packet(214),
        generate_packet(214),
    ]);
}

#[test]
fn largest_single_data_packet() {
    // Exactly the largest payload that still fits in a single (non-fragmented) packet.
    assert_roundtrip(&[generate_packet(MAX_DATA_LENGTH - 2)]);
}

#[test]
fn single_large_packet() {
    // One byte over the single-packet limit, forcing fragmentation.
    assert_roundtrip(&[generate_packet(MAX_DATA_LENGTH - 1)]);
}

#[test]
fn multiple_large_packets() {
    assert_roundtrip(&[
        generate_packet(512),
        generate_packet(512 + 7),
        generate_packet(512 + 54),
        generate_packet(512 * 2),
    ]);
}

/// The headline fuzz case: 256 packets sized 256, 512, ... up to 65536 bytes,
/// exercising deep fragmentation and many window cycles.
#[test]
fn all_the_packets() {
    let packets: Vec<Vec<u8>> = (1..=256).map(|i| generate_packet(i * 256)).collect();
    assert_roundtrip(&packets);
}
