//! Name servers on 127.0.0.1 for the tests that go through a call site
//! (ADR-022): one that receives every query and never answers, as in
//! ADR-006's measurement, and one that answers every A query with
//! 127.0.0.1.
#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boneli_https::{Resolver, ResolverConfig};

/// How often the answering server looks at its stop flag.
const POLL: Duration = Duration::from_millis(5);

/// A resolver that asks `server` only, `attempts` rounds of `try_timeout`.
pub fn resolver_for(server: SocketAddr, try_timeout: Duration, attempts: u8) -> Resolver {
    Resolver::fixed(ResolverConfig::new(vec![server], try_timeout, attempts).expect("config"))
}

/// A name server that never answers: a bound UDP socket nobody reads, so
/// every query waits in its receive queue until [`Stalled::take`] counts
/// it. No thread runs, so the count is what the kernel delivered.
pub struct Stalled {
    socket: UdpSocket,
}

impl Stalled {
    pub fn start() -> Stalled {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        Stalled { socket }
    }

    pub fn addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("addr")
    }

    /// A resolver that asks this server only.
    pub fn resolver(&self, try_timeout: Duration, attempts: u8) -> Resolver {
        resolver_for(self.addr(), try_timeout, attempts)
    }

    /// A resolver for the call-site tests with a 300 ms deadline: 250 ms
    /// tries, five rounds over this server listed three times, so 3.75 s
    /// of tries. A lookup that ignored the deadline would outlive the
    /// tests' 1 s bound, and one that outlived its call would send its
    /// next query at 500 ms, inside the 600 ms the tests watch after the
    /// call returned (the 300 ms deadline cuts the second try).
    pub fn call_site_resolver(&self) -> Resolver {
        let config = ResolverConfig::new(vec![self.addr(); 3], Duration::from_millis(250), 5)
            .expect("config");
        Resolver::fixed(config)
    }

    /// The queries that arrived since the last call, removed from the
    /// queue. Delivery over loopback is done when `send` returns, so a
    /// query sent before a lookup returned is counted by a call after it.
    pub fn take(&self) -> usize {
        let mut buf = [0u8; 1024];
        let mut count = 0;
        loop {
            match self.socket.recv(&mut buf) {
                Ok(_) => count += 1,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return count,
                Err(e) => panic!("recv: {e}"),
            }
        }
    }
}

/// A name server that answers A queries for any name with 127.0.0.1 and
/// AAAA queries with no record.
pub struct Loopback {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Loopback {
    pub fn start() -> Loopback {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket.set_read_timeout(Some(POLL)).expect("timeout");
        let addr = socket.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while !flag.load(Ordering::SeqCst) {
                let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if let Some(answer) = loopback_answer(&buf[..len]) {
                    let _ = socket.send_to(&answer, peer);
                }
            }
        });
        Loopback {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    /// A resolver that asks this server only.
    pub fn resolver(&self) -> Resolver {
        resolver_for(self.addr, Duration::from_secs(5), 1)
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The answer to `query` (header and question copied): for type A one
/// record 127.0.0.1 owned by the question name, for any other type none.
fn loopback_answer(query: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 12;
    loop {
        let len = usize::from(*query.get(pos)?);
        pos += 1 + len;
        if len == 0 {
            break;
        }
    }
    let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
    let mut msg = query.get(..pos + 4)?.to_vec();
    msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    if qtype == 1 {
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    }
    Some(msg)
}
