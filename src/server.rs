use crate::config::ServerConfig;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

pub async fn run(cfg: ServerConfig, tls_config: rustls::ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&cfg.bind_address).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // NIST SC-5: Volumetric DoS Protection
    let quota = Quota::per_second(NonZeroU32::new(cfg.max_connections_per_sec).unwrap());
    let rate_limiter = Arc::new(RateLimiter::keyed(quota));

    info!(
        action = "network_bind",
        address = %cfg.bind_address,
        status = "success",
        "Listening for RadSec connections"
    );

    // Graceful Shutdown Channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Spawn signal handler
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
        info!(action = "shutdown_signal", "Received termination signal, shutting down gracefully...");
        let _ = shutdown_tx.send(()).await;
    });

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let ip = peer_addr.ip();

                        if rate_limiter.check_key(&ip).is_err() {
                            warn!(
                                action = "rate_limit_exceeded",
                                source_ip = %ip,
                                status = "dropped",
                                "Connection dropped due to rate limiting"
                            );
                            continue;
                        }

                        let tls_acceptor = tls_acceptor.clone();

                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(_tls_stream) => {
                                    info!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        status = "success",
                                        "mTLS session established (P-384/PQ)"
                                    );
                                    // RADIUS Protocol processing goes here
                                }
                                Err(e) => {
                                    error!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        status = "failed",
                                        error = %e,
                                        "TLS handshake failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(action = "network_accept", error = %e, "Failed to accept connection");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!(action = "server_shutdown", "Server stopped accepting new connections");
                break;
            }
        }
    }

    Ok(())
}
