# soe-protocol

A Rust implementation of version 3 of the **SOE** (Sony Online Entertainment) network
protocol.

SOE is a UDP transport layer used by a number of games (Free Realms, H1Z1, Landmark,
PlanetSide 2, and others). On top of raw UDP it adds:

- **Sessions** with a negotiated handshake, heartbeats, and inactivity timeouts.
- **Packet verification** via CRC32.
- **Reliable, ordered delivery** with fragmentation and reassembly (a sliding-window
  reliable data channel in each direction).
- **Optional compression** (zlib) of contextual packets.
- **Optional encryption** (RC4) of application data.

## Design: a sans-I/O core

The crate is structured as a **sans-I/O core**: all protocol logic is a pure state
machine that performs no I/O and reads no clock. Time is supplied by the caller as a
`std::time::Instant`, and bytes are handed in and out explicitly. This keeps the core
runtime-agnostic, deterministic, and easy to test, with thin adapters layered on top
for real-world I/O.

```
        ┌─────────────────────────── adapters (opt-in) ───────────────────────────┐
        │  SyncSoeSocket (std)   TokioSoeSocket (feature = "tokio")                 │
        │                        TokioSoeServer + SoeHandle (feature = "tokio")     │
        └──────────────────────────────────┬───────────────────────────────────────┘
                                            │ drives
        ┌───────────────────────────────────▼──────────────────────────────────────┐
        │  SoeMultiplexer<A>   — demultiplexes many sessions by remote address       │
        │  SoeSession          — one session's state machine                         │
        │  channels / packets / crc32 / rc4 / zlib / varint — protocol primitives    │
        └───────────────────────────────────────────────────────────────────────────┘
```

- **`SoeSession`** — the state machine for a single session: handshake, reliable
  channels, heartbeats, and termination.
- **`SoeMultiplexer<A>`** — demultiplexes datagrams from many remotes (generic over
  the address type `A`) into per-session `SoeSession`s. You feed it incoming datagrams
  and ticks; it surfaces datagrams to send and lifecycle/data events.
- **Adapters** — optional convenience drivers that own a real socket and pump the
  core. The default build pulls in **zero** async dependencies; the Tokio adapters are
  gated behind the `tokio` feature.

## Installation

```toml
[dependencies]
soe-protocol = "0.1"

# For the async (Tokio) adapters:
soe-protocol = { version = "0.1", features = ["tokio"] }
```

Requires Rust 1.88+ (edition 2024).

## Quick start

Configure a socket with the application protocol both peers agree on, then drive it.
The synchronous adapter needs no extra dependencies:

```rust
use std::time::Duration;
use soe_protocol::{SessionParameters, SyncSoeSocket};
use soe_protocol::socket::{SocketConfig, SocketEvent, SoeSocket};

let config = SocketConfig {
    default_session_params: SessionParameters {
        application_protocol: "MyGame".to_owned(),
        ..SessionParameters::default()
    },
    ..SocketConfig::default()
};

// Bind and tick every 5ms.
let mut socket = SyncSoeSocket::bind("0.0.0.0:20260".parse().unwrap(), config, Duration::from_millis(5))?;

loop {
    // One read-or-tick cycle; returns any events produced.
    for event in socket.step()? {
        match event {
            SocketEvent::SessionOpened { remote } => println!("opened {remote}"),
            SocketEvent::DataReceived { remote, data } => {
                socket.enqueue_data(&remote, &data); // echo it back
            }
            SocketEvent::SessionClosed { remote, reason } => println!("closed {remote}: {reason:?}"),
        }
    }
}
# Ok::<(), std::io::Error>(())
```

To act as a client, call `socket.connect(server_addr)` instead of waiting for an
inbound session.

## Writing a game server

UDP has no per-connection socket: every client's datagrams arrive on the one bound
socket, and a SOE session is inherently single-owner (sequence numbers, RC4 cipher
state, and fragment reassembly must be mutated by one task at a time). So rather than a
socket-per-client task as you might use with TCP, the recommended shape is **one driver
task that owns the socket and all protocol state, with per-client game logic running on
its own tasks**, talking to the driver over channels.

The `tokio` feature provides this out of the box via **`TokioSoeServer`** and its
cloneable **`SoeHandle`**:

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use soe_protocol::SessionParameters;
use soe_protocol::socket::{SocketConfig, SocketEvent};
use soe_protocol::tokio_rt::{SoeHandle, TokioSoeServer};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = SocketConfig {
        default_session_params: SessionParameters {
            application_protocol: "MyGame".to_owned(),
            ..SessionParameters::default()
        },
        ..SocketConfig::default()
    };

    // The driver task owns the socket and all protocol state.
    let mut server = TokioSoeServer::bind("0.0.0.0:20260".parse().unwrap(), config, Duration::from_millis(5)).await?;

    // One inbound channel per connected client; each client task owns its receiver.
    let mut clients: HashMap<SocketAddr, mpsc::UnboundedSender<Bytes>> = HashMap::new();

    while let Some(event) = server.recv_event().await {
        match event {
            SocketEvent::SessionOpened { remote } => {
                let (tx, rx) = mpsc::unbounded_channel();
                clients.insert(remote, tx);
                tokio::spawn(client_task(remote, server.handle(), rx));
            }
            SocketEvent::DataReceived { remote, data } => {
                if let Some(tx) = clients.get(&remote) {
                    let _ = tx.send(data); // route to that client's task
                }
            }
            SocketEvent::SessionClosed { remote, .. } => {
                clients.remove(&remote);
            }
        }
    }
    Ok(())
}

// Per-client game logic runs concurrently and replies via the shared handle.
async fn client_task(remote: SocketAddr, handle: SoeHandle, mut inbound: mpsc::UnboundedReceiver<Bytes>) {
    while let Some(data) = inbound.recv().await {
        handle.enqueue_data(remote, data); // echo
    }
}
```

`SoeHandle` is `Clone`/`Send` and exposes `connect`, `enqueue_data`, and `terminate`;
all are non-blocking and simply post a command to the driver loop. Events are received
in an order that guarantees a session's `SessionOpened` is surfaced **before** any of
its `DataReceived`, and `SessionClosed` **after** — so per-session state (like the task
spawned above) is always in place before that session's data arrives.

### Scaling across cores

A single UDP receive loop comfortably dispatches far more packets per second than a
game simulation typically consumes, so one `TokioSoeServer` is usually plenty. If
profiling ever shows the I/O task saturating a core, scale out by running several
servers — one per `SO_REUSEPORT` socket — and routing by client address. Because each
server owns its own socket and `SoeMultiplexer`, this requires no changes to the core.

## Examples

Runnable examples live in [`examples/`](examples/):

| Example                       | Feature  | Description                                        |
| ----------------------------- | -------- | -------------------------------------------------- |
| `server-sync` / `client-sync` | —        | Blocking, std-only echo server and ping client.    |
| `server-tokio` / `client-tokio` | `tokio` | Async echo server and ping client.               |
| `server-actor`                | `tokio`  | Game-server skeleton: per-client-task fan-out.     |

Run a ping-pong over real UDP:

```sh
# std-only
cargo run --example server-sync -- 127.0.0.1:20260
cargo run --example client-sync -- 127.0.0.1:20260

# Tokio
cargo run --features tokio --example server-tokio -- 127.0.0.1:20260
cargo run --features tokio --example client-tokio -- 127.0.0.1:20260

# Actor-style game server
cargo run --features tokio --example server-actor -- 127.0.0.1:20260
cargo run --features tokio --example client-tokio -- 127.0.0.1:20260
```

## Bring your own runtime

You don't need either bundled adapter. The core, `SoeMultiplexer`, has no I/O
dependency: feed it incoming datagrams with `process_incoming(remote, datagram, now)`,
call `run_tick(now)` periodically, and flush whatever `take_outgoing()` returns over
your own socket, reading events from `take_events()`. The `UdpTransport` trait and
`SoeMultiplexer::drive` offer a minimal, dependency-free seam for any non-blocking UDP
socket (with a blanket impl for `std::net::UdpSocket`).

## Acknowledgements

This implementation is a port informed by the public C# and Zig implementations in
[Sanctuary.SoeProtocol](https://github.com/PS2Sanctuary/Sanctuary.SoeProtocol).

## License

Licensed under GPL-3.0-or-later. See [LICENSE](LICENSE).
