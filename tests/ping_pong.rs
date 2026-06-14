//! Two-peer ping-pong integration test over real loopback UDP sockets.
//!
//! Mirrors the reference's single-session peer sample: a client and server each
//! drive a [`SoeMultiplexer`] over their own non-blocking [`UdpSocket`], exchanging
//! reliable application data through a fully negotiated SOE session. This exercises
//! the whole stack end-to-end (negotiation, framing, CRC, reliable data, acks)
//! without any async runtime.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeMultiplexer};

const APP_PROTOCOL: &str = "SoePingPong";
const ROUNDS: usize = 5;

fn config(seed: u64) -> SocketConfig {
    SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: APP_PROTOCOL.to_owned(),
            ..SessionParameters::default()
        },
        base_rng_seed: seed,
        ..SocketConfig::default()
    }
}

#[test]
fn ping_pong_over_real_udp() {
    let mut server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    let mut client_sock = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    server_sock.set_nonblocking(true).unwrap();
    client_sock.set_nonblocking(true).unwrap();
    let server_addr: SocketAddr = server_sock.local_addr().unwrap();

    let mut server = SoeMultiplexer::<SocketAddr>::new(config(2));
    let mut client = SoeMultiplexer::<SocketAddr>::new(config(1));

    client.connect(server_addr, Instant::now());

    let mut client_sends = 0usize;
    let mut server_echoes = 0usize;
    let mut client_echoes_seen = 0usize;
    let mut client_opened = false;

    // Bounded drive loop; localhost UDP settles well within this budget.
    for _ in 0..5000 {
        let now = Instant::now();
        server.drive(&mut server_sock, now).unwrap();
        client.drive(&mut client_sock, now).unwrap();

        for event in server.take_events() {
            if let SocketEvent::DataReceived { remote, data } = event {
                assert_eq!(data, format!("ping {server_echoes}").as_bytes());
                server_echoes += 1;
                // Echo the ping straight back.
                assert!(server.enqueue_data(&remote, &data));
            }
        }

        for event in client.take_events() {
            match event {
                SocketEvent::SessionOpened { .. } if !client_opened => {
                    client_opened = true;
                    assert!(
                        client
                            .enqueue_data(&server_addr, format!("ping {client_sends}").as_bytes())
                    );
                    client_sends += 1;
                }
                SocketEvent::DataReceived { data, .. } => {
                    assert_eq!(data, format!("ping {client_echoes_seen}").as_bytes());
                    client_echoes_seen += 1;
                    if client_sends < ROUNDS {
                        assert!(
                            client.enqueue_data(
                                &server_addr,
                                format!("ping {client_sends}").as_bytes()
                            )
                        );
                        client_sends += 1;
                    }
                }
                _ => {}
            }
        }

        if client_echoes_seen >= ROUNDS {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    assert!(client_opened, "client session never opened");
    assert_eq!(
        client_echoes_seen, ROUNDS,
        "client did not receive all {ROUNDS} echoes (got {client_echoes_seen})"
    );
}
