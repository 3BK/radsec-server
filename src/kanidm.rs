use crate::config::UpstreamConfig;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct KanidmRadiusClient {
    upstream_addr: SocketAddr,
    timeout: Duration,
    max_packet_size: usize,
}

impl KanidmRadiusClient {
    pub fn new(
        cfg: &UpstreamConfig,
        max_packet_size: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let upstream_addr: SocketAddr = cfg.address.parse()?;
        Ok(Self {
            upstream_addr,
            timeout: Duration::from_secs(cfg.timeout_secs),
            max_packet_size,
        })
    }

    pub async fn exchange(
        &self,
        request: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = if self.upstream_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(self.upstream_addr).await?;

        timeout(self.timeout, socket.send(request)).await??;

        let mut buf = vec![0u8; self.max_packet_size];
        let n = timeout(self.timeout, socket.recv(&mut buf)).await??;

        buf.truncate(n);
        Ok(buf)
    }
}
