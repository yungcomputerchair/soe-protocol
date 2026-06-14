//! A SOE game-server skeleton built on the actor-style [`TokioSoeServer`].
//!
//! Run with: `cargo run --features tokio --example server-actor -- 127.0.0.1:20260`
//!
//! This demonstrates the recommended topology for a game server over UDP:
//!
//! * One driver task (owned by [`TokioSoeServer`]) owns the socket and all protocol
//!   state. We never touch protocol state directly.
//! * A small router loop here consumes events and fans them out to **one Tokio task
//!   per client**, where per-client game logic lives.
//! * Each per-client task holds a cloned [`SoeHandle`] and sends reliable data back
//!   through the driver, fully decoupled from other clients.
//!
//! The per-client logic here is a trivial echo, but it runs concurrently per client
//! and is where real game-state handling would go.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent};
use soe_protocol::tokio_rt::{SoeHandle, TokioSoeServer};
use tokio::sync::mpsc;

const APP_PROTOCOL: &str = "SoePingPong";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind_addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:20260".to_owned())
        .parse()
        .expect("a valid bind address");

    let config = SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: APP_PROTOCOL.to_owned(),
            ..SessionParameters::default()
        },
        ..SocketConfig::default()
    };

    let mut server = TokioSoeServer::bind(bind_addr, config, Duration::from_millis(5)).await?;
    println!("server: listening on {}", server.local_addr());

    // One inbound-data channel per connected client. The router owns the senders;
    // each per-client task owns its receiver.
    let mut clients: HashMap<SocketAddr, mpsc::UnboundedSender<Bytes>> = HashMap::new();

    while let Some(event) = server.recv_event().await {
        match event {
            SocketEvent::SessionOpened { remote } => {
                println!("server: session opened with {remote}, spawning handler");
                let (tx, rx) = mpsc::unbounded_channel();
                clients.insert(remote, tx);
                tokio::spawn(client_task(remote, server.handle(), rx));
            }
            SocketEvent::DataReceived { remote, data } => {
                // Route the datagram to that client's task. Drop if it has gone away.
                if let Some(tx) = clients.get(&remote) {
                    let _ = tx.send(data);
                }
            }
            SocketEvent::SessionClosed { remote, reason } => {
                println!("server: session with {remote} closed ({reason:?})");
                clients.remove(&remote);
            }
        }
    }

    Ok(())
}

/// Per-client game logic: runs on its own task, receives this client's inbound data,
/// and replies via the shared [`SoeHandle`]. Ends when the session closes (its sender
/// is dropped by the router).
async fn client_task(
    remote: SocketAddr,
    handle: SoeHandle,
    mut inbound: mpsc::UnboundedReceiver<Bytes>,
) {
    while let Some(data) = inbound.recv().await {
        let text = String::from_utf8_lossy(&data);
        println!("client-task {remote}: received {text:?}, echoing");
        handle.enqueue_data(remote, data);
    }
    println!("client-task {remote}: shutting down");
}
