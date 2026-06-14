//! A synchronous, dependency-free adapter driving a [`SoeMultiplexer`] over a
//! blocking [`std::net::UdpSocket`]. Always available; pulls in no async runtime.
//!
//! The sans-I/O [`SoeMultiplexer`] is runtime-agnostic; this module is a thin
//! convenience layer mirroring [`crate::tokio_rt::TokioSoeSocket`] for callers who
//! prefer a plain blocking loop. Both types implement [`SoeSocket`].

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::protocol::DisconnectReason;
use crate::socket::{SocketConfig, SocketEvent, SoeMultiplexer, SoeSocket};

/// Buffer size for a single received datagram. SOE UDP lengths default to 512 and
/// rarely exceed it.
const RECV_BUFFER_SIZE: usize = 2048;

/// A synchronous SOE socket: a [`SoeMultiplexer`] driven over a blocking
/// [`std::net::UdpSocket`].
///
/// Drive it by repeatedly calling [`step`](SyncSoeSocket::step), which performs a
/// single read-or-tick cycle and returns any [`SocketEvent`]s produced. The socket
/// is given a read timeout equal to the tick period, so `step` returns promptly when
/// a datagram arrives and otherwise wakes once per tick to run housekeeping.
#[derive(Debug)]
pub struct SyncSoeSocket {
    mux: SoeMultiplexer<SocketAddr>,
    socket: UdpSocket,
    buf: Box<[u8]>,
}

impl SyncSoeSocket {
    /// Binds a UDP socket to `local` and prepares to drive sessions, waking at least
    /// once every `tick_period` to run housekeeping. A period of 1–10ms is typical.
    pub fn bind(
        local: SocketAddr,
        config: SocketConfig,
        tick_period: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        // A read timeout paces the loop: recv_from returns immediately on data, or
        // after the tick period so heartbeats, timeouts, and resends still run.
        socket.set_read_timeout(Some(tick_period))?;

        Ok(Self {
            mux: SoeMultiplexer::new(config),
            socket,
            buf: vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice(),
        })
    }

    /// Performs a single drive cycle: waits up to the tick period for an incoming
    /// datagram, runs a session tick, flushes outgoing datagrams, and returns any
    /// events.
    pub fn step(&mut self) -> io::Result<Vec<SocketEvent<SocketAddr>>> {
        match self.socket.recv_from(&mut self.buf) {
            Ok((len, from)) => {
                let datagram = Bytes::copy_from_slice(&self.buf[..len]);
                self.mux.process_incoming(from, datagram, Instant::now());
            }
            // A read timeout surfaces as WouldBlock or TimedOut depending on the
            // platform; both simply mean "no datagram this tick".
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => return Err(e),
        }

        self.mux.run_tick(Instant::now());

        for (addr, datagram) in self.mux.take_outgoing() {
            self.socket.send_to(&datagram, addr)?;
        }

        Ok(self.mux.take_events())
    }
}

impl SoeSocket for SyncSoeSocket {
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
