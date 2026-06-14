//! A [Tokio](https://tokio.rs)-based async adapter driving a [`SoeMultiplexer`]
//! over a UDP socket. Enabled by the `tokio` feature.
//!
//! The sans-I/O [`SoeMultiplexer`] is runtime-agnostic; this module is a thin,
//! optional convenience layer for users who want a ready-made async driver. It owns
//! a [`tokio::net::UdpSocket`] and interleaves socket reads with periodic ticks
//! (for heartbeats, timeouts, and reliable-data resends), flushing outgoing
//! datagrams after each step.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};

use crate::protocol::DisconnectReason;
use crate::socket::{SocketConfig, SocketEvent, SoeMultiplexer, SoeSocket};

/// Buffer size for a single received datagram. SOE UDP lengths default to 512 and
/// rarely exceed it.
const RECV_BUFFER_SIZE: usize = 2048;

/// An async SOE socket: a [`SoeMultiplexer`] driven over a Tokio UDP socket.
///
/// Drive it by repeatedly awaiting [`step`](TokioSoeSocket::step), which performs a
/// single read-or-tick cycle and returns any [`SocketEvent`]s produced. Sessions are
/// initiated with [`connect`](TokioSoeSocket::connect) and data is sent with
/// [`enqueue_data`](TokioSoeSocket::enqueue_data).
#[derive(Debug)]
pub struct TokioSoeSocket {
    mux: SoeMultiplexer<SocketAddr>,
    socket: UdpSocket,
    tick: Interval,
    buf: Box<[u8]>,
}

impl TokioSoeSocket {
    /// Binds a UDP socket to `local` and prepares to drive sessions, ticking every
    /// `tick_period`. A period of 1–10ms is typical.
    pub async fn bind(
        local: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        let mut tick = interval(tick_period);
        // If we fall behind (e.g. while awaiting a send), don't fire a burst of
        // catch-up ticks; a single delayed tick is enough.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        Ok(Self {
            mux: SoeMultiplexer::new(config),
            socket,
            tick,
            buf: vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice(),
        })
    }

    /// Returns the local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Performs a single drive cycle: awaits either an incoming datagram or the next
    /// tick, runs a session tick, flushes outgoing datagrams, and returns any events.
    pub async fn step(&mut self) -> io::Result<Vec<SocketEvent<SocketAddr>>> {
        tokio::select! {
            result = self.socket.recv_from(&mut self.buf) => {
                let (len, from) = result?;
                let datagram = Bytes::copy_from_slice(&self.buf[..len]);
                self.mux.process_incoming(from, datagram, Instant::now());
            }
            _ = self.tick.tick() => {}
        }

        self.mux.run_tick(Instant::now());

        for (addr, datagram) in self.mux.take_outgoing() {
            self.socket.send_to(&datagram, addr).await?;
        }

        Ok(self.mux.take_events())
    }
}

impl SoeSocket for TokioSoeSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn session_count(&self) -> usize {
        self.mux.session_count()
    }

    fn connect(&mut self, remote: SocketAddr) {
        self.mux.connect(remote, Instant::now());
    }

    fn enqueue_data(&mut self, remote: &SocketAddr, data: &[u8]) -> bool {
        self.mux.enqueue_data(remote, data)
    }

    fn terminate(&mut self, remote: &SocketAddr, reason: DisconnectReason) {
        self.mux.terminate(remote, reason, Instant::now());
    }
}

/// A command sent from a [`SoeHandle`] to the [`TokioSoeServer`] driver loop.
enum Command {
    Connect(SocketAddr),
    EnqueueData {
        remote: SocketAddr,
        data: Bytes,
    },
    Terminate {
        remote: SocketAddr,
        reason: DisconnectReason,
    },
}

/// A cloneable handle for interacting with a [`TokioSoeServer`] from any task.
///
/// All methods are non-blocking: they post a command to the server's driver loop,
/// which owns the socket and the [`SoeMultiplexer`]. This lets per-client game-logic
/// tasks send reliable data and manage sessions without sharing the (necessarily
/// single-owner) protocol state.
///
/// Each method returns `false` if the server's driver loop has stopped (e.g. the
/// [`TokioSoeServer`] was dropped), in which case the command was not delivered.
#[derive(Clone, Debug)]
pub struct SoeHandle {
    commands: mpsc::UnboundedSender<Command>,
}

impl SoeHandle {
    /// Opens a client session to `remote`. The session request is sent by the driver
    /// loop on its next cycle.
    pub fn connect(&self, remote: SocketAddr) -> bool {
        self.commands.send(Command::Connect(remote)).is_ok()
    }

    /// Enqueues application data to be sent reliably to `remote`.
    ///
    /// Returns `false` only if the driver loop has stopped; it does **not** report
    /// whether a session for `remote` exists (that is determined asynchronously by
    /// the loop).
    pub fn enqueue_data(&self, remote: SocketAddr, data: impl Into<Bytes>) -> bool {
        self.commands
            .send(Command::EnqueueData {
                remote,
                data: data.into(),
            })
            .is_ok()
    }

    /// Terminates the session with `remote`, notifying the remote party.
    pub fn terminate(&self, remote: SocketAddr, reason: DisconnectReason) -> bool {
        self.commands
            .send(Command::Terminate { remote, reason })
            .is_ok()
    }
}

/// An actor-style SOE server: a [`SoeMultiplexer`] driven on its own Tokio task,
/// reachable from any task via a cloneable [`SoeHandle`].
///
/// This is the recommended shape for a game server. The driver task owns the UDP
/// socket and all protocol state (sequence numbers, ciphers, reassembly), which is
/// inherently single-owner. Application code interacts with it asynchronously:
///
/// * Obtain a cloneable [`SoeHandle`] with [`handle`](TokioSoeServer::handle) and
///   share it with per-client game-logic tasks to send data or manage sessions.
/// * Receive [`SocketEvent`]s with [`recv_event`](TokioSoeServer::recv_event) and
///   route them (e.g. fan `DataReceived` out to the matching per-client task).
///
/// Because each server owns one socket and one multiplexer, scaling UDP I/O across
/// cores later is a matter of running several servers — one per `SO_REUSEPORT`
/// socket — and routing by client address; no change to the core is required.
///
/// The driver task runs until the [`TokioSoeServer`] **and** every [`SoeHandle`] are
/// dropped, or until the event receiver is dropped.
#[derive(Debug)]
pub struct TokioSoeServer {
    handle: SoeHandle,
    events: mpsc::UnboundedReceiver<SocketEvent<SocketAddr>>,
    local_addr: SocketAddr,
    driver: JoinHandle<()>,
}

impl TokioSoeServer {
    /// Binds a UDP socket to `local` and spawns the driver loop, ticking every
    /// `tick_period`. A period of 1–10ms is typical.
    pub async fn bind(
        local: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        let local_addr = socket.local_addr()?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let driver = tokio::spawn(drive_loop(
            socket,
            config,
            tick_period,
            command_rx,
            event_tx,
        ));

        Ok(Self {
            handle: SoeHandle {
                commands: command_tx,
            },
            events: event_rx,
            local_addr,
            driver,
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns a cloneable handle for sending commands to the server from any task.
    pub fn handle(&self) -> SoeHandle {
        self.handle.clone()
    }

    /// Awaits the next event from the driver loop, or `None` once the loop has
    /// stopped.
    pub async fn recv_event(&mut self) -> Option<SocketEvent<SocketAddr>> {
        self.events.recv().await
    }

    /// Aborts the driver task, stopping the server.
    pub fn abort(&self) {
        self.driver.abort();
    }
}

/// The actor driver loop: owns the socket and multiplexer, interleaving socket
/// reads, periodic ticks, and commands from [`SoeHandle`]s, flushing outgoing
/// datagrams and forwarding events after each cycle.
async fn drive_loop(
    socket: UdpSocket,
    config: SocketConfig,
    tick_period: Duration,
    mut commands: mpsc::UnboundedReceiver<Command>,
    events: mpsc::UnboundedSender<SocketEvent<SocketAddr>>,
) {
    let mut mux = SoeMultiplexer::new(config);
    let mut tick = interval(tick_period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut buf = vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice();

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, from)) => {
                        let datagram = Bytes::copy_from_slice(&buf[..len]);
                        mux.process_incoming(from, datagram, Instant::now());
                    }
                    // A transient receive error (e.g. ICMP port-unreachable surfaced
                    // on some platforms) shouldn't kill the server; skip and continue.
                    Err(_) => continue,
                }
            }
            _ = tick.tick() => {
                mux.run_tick(Instant::now());
            }
            command = commands.recv() => {
                match command {
                    Some(Command::Connect(remote)) => mux.connect(remote, Instant::now()),
                    Some(Command::EnqueueData { remote, data }) => {
                        // Fire-and-forget: if no running session exists for `remote`
                        // the data is dropped (the handle API is intentionally async
                        // and can't synchronously report this).
                        let _ = mux.enqueue_data(&remote, &data);
                    }
                    Some(Command::Terminate { remote, reason }) => {
                        mux.terminate(&remote, reason, Instant::now());
                    }
                    // All handles dropped: nothing more can drive the server.
                    None => break,
                }
            }
        }

        for (addr, datagram) in mux.take_outgoing() {
            // A send failure for one datagram shouldn't tear down every session.
            let _ = socket.send_to(&datagram, addr).await;
        }
        for event in mux.take_events() {
            // The event receiver was dropped: no one is listening, so shut down.
            if events.send(event).is_err() {
                return;
            }
        }
    }
}
