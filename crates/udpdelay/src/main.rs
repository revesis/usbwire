//! udpdelay LISTEN UPSTREAM ONE_WAY_MS
//!
//! Relays one UDP client to UPSTREAM, delaying every datagram by ONE_WAY_MS
//! in each direction (so RTT grows by 2 × ONE_WAY_MS). Order is preserved.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Instant, sleep_until};

/// FIFO delay line: since the delay is constant, deadlines are monotonic.
fn delay_line(sock: Arc<UdpSocket>, delay: Duration) -> mpsc::UnboundedSender<(Vec<u8>, SocketAddr)> {
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>, SocketAddr)>();
    tokio::spawn(async move {
        while let Some((due, pkt, to)) = rx.recv().await {
            sleep_until(due).await;
            let _ = sock.send_to(&pkt, to).await;
        }
    });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
    tokio::spawn(async move {
        while let Some((pkt, to)) = in_rx.recv().await {
            let _ = tx.send((Instant::now() + delay, pkt, to));
        }
    });
    in_tx
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: udpdelay LISTEN UPSTREAM ONE_WAY_MS";
    let listen: SocketAddr = a.first().context(usage)?.parse()?;
    let upstream: SocketAddr = a.get(1).context(usage)?.parse()?;
    let delay = Duration::from_millis(a.get(2).context(usage)?.parse()?);

    let front = Arc::new(UdpSocket::bind(listen).await?);
    let back = Arc::new(UdpSocket::bind(if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?);
    let to_upstream = delay_line(back.clone(), delay);
    let to_client = delay_line(front.clone(), delay);
    let client: Arc<Mutex<Option<SocketAddr>>> = Default::default();
    eprintln!("udpdelay {listen} -> {upstream}, +{delay:?} each way");

    let c = client.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, _)) = back.recv_from(&mut buf).await {
            if let Some(cl) = *c.lock().await {
                let _ = to_client.send((buf[..n].to_vec(), cl));
            }
        }
    });
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, from) = front.recv_from(&mut buf).await?;
        *client.lock().await = Some(from);
        let _ = to_upstream.send((buf[..n].to_vec(), upstream));
    }
}
