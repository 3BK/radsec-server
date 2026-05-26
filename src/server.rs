use crate::config::Config;
use crate::control::{
    spawn_control_event_drain, spawn_shadow_actor, ControlEvent, ControlTx, ShadowTx, ShadowWork,
};
use crate::crypto::{extract_peer_identity, verify_peer_identity, PeerIdentity};
use crate::eap::{enforce_eap_tls_only, parse_eap_message, EAP_TYPE_IDENTITY, EAP_TYPE_TLS};
use crate::kanidm::KanidmRadiusClient;
use crate::metrics::{spawn_metrics_actor, MetricSample, MetricsTx};
use crate::radius::{
    RadiusPacket, ATTR_EAP_MESSAGE, CODE_ACCESS_ACCEPT, CODE_ACCESS_CHALLENGE, CODE_ACCESS_REJECT,
    CODE_ACCESS_REQUEST,
};
use crate::state::{SessionState, SessionTracker};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn run(
    cfg: Config,
    tls_config: rustls::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&cfg.server.bind_address).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let kanidm_client = Arc::new(KanidmRadiusClient::new(
        &cfg.upstream,
        cfg.radius.max_packet_size,
    )?);

    let quota =
        Quota::per_second(NonZeroU32::new(cfg.server.max_connections_per_sec).unwrap());
    let rate_limiter = Arc::new(RateLimiter::keyed(quota));

    let limiter_clone = rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter_clone.retain_recent();
            debug!(action = "rate_limiter_sweep", "Rate limiter memory swept");
        }
    });

    let control_tx = if cfg.control_plane.enabled {
        let (tx, rx) = mpsc::channel(cfg.control_plane.queue_capacity);
        spawn_control_event_drain(rx);
        Some(tx)
    } else {
        None
    };

    let shadow_tx: Option<ShadowTx> = if cfg.control_plane.enabled && cfg.control_plane.shadow_mode {
        let (tx, rx) = mpsc::channel(cfg.control_plane.shadow_queue_capacity);
        spawn_shadow_actor(rx, control_tx.clone());
        Some(tx)
    } else {
        None
    };

    let metrics_tx = if cfg.metrology.enabled {
        let (tx, rx) = mpsc::channel(cfg.metrology.queue_capacity);
        spawn_metrics_actor(rx, cfg.metrology.flush_interval_secs);
        Some(tx)
    } else {
        None
    };

    info!(
        action = "network_bind",
        address = %cfg.server.bind_address,
        status = "success",
        mode = "radsec_edge_proxy",
        upstream = %cfg.upstream.address,
        eap_mode = "eap-tls-only",
        ndt_shadow = cfg.control_plane.shadow_mode,
        metrology = cfg.metrology.enabled,
        "Listening for RadSec connections"
    );

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let shutdown_grace = cfg.server.shutdown_grace_secs;

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
        info!(
            action = "shutdown_signal",
            status = "received",
            "Received termination signal"
        );
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
                                "Connection dropped due to rate limiting"
                            );
                            if let Some(tx) = &metrics_tx {
                                let _ = tx.try_send(MetricSample::Reject("reject_policy"));
                            }
                            continue;
                        }

                        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
                        let tls_acceptor = tls_acceptor.clone();
                        let cfg_clone = cfg.clone();
                        let kanidm_clone = kanidm_client.clone();
                        let control_tx_clone = control_tx.clone();
                        let shadow_tx_clone = shadow_tx.clone();
                        let metrics_tx_clone = metrics_tx.clone();

                        tokio::spawn(async move {
                            let mut tracker =
                                SessionTracker::new(session_id, control_tx_clone.clone(), metrics_tx_clone.clone());

                            if let Some(tx) = &control_tx_clone {
                                let _ = tx.try_send(ControlEvent::SessionOpened {
                                    session_id,
                                    source_ip: ip,
                                });
                            }
                            if let Some(tx) = &metrics_tx_clone {
                                let _ = tx.try_send(MetricSample::SessionOpened);
                            }

                            if tracker.transition(SessionState::TlsHandshakeStarted, "tcp_accepted").is_err() {
                                return;
                            }

                            let hs_start = Instant::now();
                            let handshake = timeout(
                                Duration::from_secs(cfg_clone.server.handshake_timeout_secs),
                                tls_acceptor.accept(stream)
                            ).await;

                            match handshake {
                                Ok(Ok(tls_stream)) => {
                                    let hs_ms = hs_start.elapsed().as_millis() as u64;
                                    emit_metric(&metrics_tx_clone, MetricSample::TlsHandshakeMs(hs_ms));

                                    if let Err(e) = tracker.transition(SessionState::TlsEstablished, "outer_tls_ok") {
                                        error!(action = "state_transition", session_id, error = %e);
                                        return;
                                    }

                                    let (_, conn) = tls_stream.get_ref();
                                    let peer_certs = match conn.peer_certificates() {
                                        Some(certs) if !certs.is_empty() => certs,
                                        _ => {
                                            error!(
                                                action = "tls_handshake",
                                                source_ip = %ip,
                                                error = "no_peer_certificate",
                                                "TLS handshake succeeded without peer certificate"
                                            );
                                            let _ = tracker.transition(SessionState::Error, "missing_peer_cert");
                                            return;
                                        }
                                    };

                                    let peer_identity = match extract_peer_identity(&peer_certs[0]) {
                                        Ok(identity) => identity,
                                        Err(e) => {
                                            error!(
                                                action = "peer_identity_extract",
                                                source_ip = %ip,
                                                error = %e,
                                                "Failed to parse peer certificate"
                                            );
                                            let _ = tracker.transition(SessionState::Error, "peer_cert_parse_fail");
                                            return;
                                        }
                                    };

                                    if let Err(e) = verify_peer_identity(&peer_identity, &cfg_clone.peer_policy) {
                                        warn!(
                                            action = "peer_identity_policy",
                                            source_ip = %ip,
                                            error = %e,
                                            fingerprint_sha256 = %peer_identity.fingerprint_sha256_hex,
                                            "Peer certificate denied by policy"
                                        );
                                        emit_metric(&metrics_tx_clone, MetricSample::Reject("reject_policy"));
                                        let _ = tracker.transition(SessionState::Error, "peer_policy_deny");
                                        return;
                                    }

                                    if let Some(tx) = &control_tx_clone {
                                        let _ = tx.try_send(ControlEvent::PeerIdentity {
                                            session_id,
                                            fingerprint_sha256: peer_identity.fingerprint_sha256_hex.clone(),
                                            subject_cn: peer_identity.subject_cn.clone(),
                                            san_uris: peer_identity.san_uris.clone(),
                                            san_dns: peer_identity.san_dns.clone(),
                                        });
                                    }

                                    if let Err(e) = tracker.transition(SessionState::PeerIdentityValidated, "peer_identity_ok") {
                                        error!(action = "state_transition", session_id, error = %e);
                                        return;
                                    }

                                    info!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        session_id = session_id,
                                        fingerprint_sha256 = %peer_identity.fingerprint_sha256_hex,
                                        peer_cn = %peer_identity.subject_cn.as_deref().unwrap_or(""),
                                        peer_san_uris = ?peer_identity.san_uris,
                                        peer_san_dns = ?peer_identity.san_dns,
                                        "mTLS session established"
                                    );

                                    match radsec_stream_handler(
                                        tls_stream,
                                        cfg_clone,
                                        kanidm_clone,
                                        peer_identity,
                                        tracker,
                                        control_tx_clone,
                                        shadow_tx_clone,
                                        metrics_tx_clone,
                                    ).await {
                                        Ok(_) => info!(
                                            action = "radius_session",
                                            source_ip = %ip,
                                            session_id = session_id,
                                            status = "closed"
                                        ),
                                        Err(e) => error!(
                                            action = "radius_session",
                                            source_ip = %ip,
                                            session_id = session_id,
                                            error = %e
                                        ),
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        session_id = session_id,
                                        error = %e,
                                        "TLS handshake failed"
                                    );
                                    let _ = tracker.transition(SessionState::Error, "tls_handshake_fail");
                                }
                                Err(_) => {
                                    warn!(
                                        action = "tls_handshake_timeout",
                                        source_ip = %ip,
                                        session_id = session_id,
                                        "TLS handshake timed out"
                                    );
                                    let _ = tracker.transition(SessionState::Error, "tls_handshake_timeout");
                                }
                            }

                            if let Some(tx) = &metrics_tx_clone {
                                let _ = tx.try_send(MetricSample::SessionClosed);
                            }
                        });
                    }
                    Err(e) => error!(action = "network_accept", error = %e),
                }
            }
            _ = shutdown_rx.recv() => {
                info!(
                    action = "server_shutdown",
                    grace_secs = shutdown_grace,
                    "Server stopped accepting new connections"
                );
                break;
            }
        }
    }

    Ok(())
}

async fn radsec_stream_handler(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    cfg: Config,
    kanidm: Arc<KanidmRadiusClient>,
    peer_identity: PeerIdentity,
    mut tracker: SessionTracker,
    control_tx: Option<ControlTx>,
    shadow_tx: Option<ShadowTx>,
    metrics_tx: Option<MetricsTx>,
) -> Result<(), std::io::Error> {
    let io_timeout = Duration::from_secs(cfg.server.io_timeout_secs);
    let mut header_buf = [0u8; 4];

    loop {
        match timeout(io_timeout, stream.read_exact(&mut header_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracker.close();
                info!(action = "tls_session_end", session_id = tracker.session_id(), "Client disconnected gracefully");
                break;
            }
            Ok(Err(e)) => {
                let _ = tracker.transition(SessionState::Error, "read_header_fail");
                return Err(e);
            }
            Err(_) => {
                let _ = tracker.transition(SessionState::Error, "read_header_timeout");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out waiting for packet header",
                ));
            }
        }

        let length = u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize;
        if !(20..=cfg.radius.max_packet_size).contains(&length) {
            let _ = tracker.transition(SessionState::Error, "packet_length_invalid");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid RADIUS packet length: {}", length),
            ));
        }

        let mut payload = vec![0u8; length - 4];
        match timeout(io_timeout, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let _ = tracker.transition(SessionState::Error, "read_payload_fail");
                return Err(e);
            }
            Err(_) => {
                let _ = tracker.transition(SessionState::Error, "read_payload_timeout");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out waiting for packet payload",
                ));
            }
        }

        let mut full_packet = header_buf.to_vec();
        full_packet.extend_from_slice(&payload);

        emit_metric(&metrics_tx, MetricSample::PacketRx(length));

        if let Some(tx) = &shadow_tx {
            let work = ShadowWork {
                session_id: tracker.session_id(),
                packet: full_packet.clone(),
                max_packet_size: cfg.radius.max_packet_size,
                require_message_authenticator: cfg.radius.require_message_authenticator,
                shared_secret: cfg.radius.shared_secret.clone(),
                enforce_eap_tls_only: cfg.eap.enforce_eap_tls_only,
            };
            if tx.try_send(work).is_err() {
                emit_metric(&metrics_tx, MetricSample::QueueDrop("queue_drop_shadow"));
            }
        }

        if let Err(e) = tracker.transition(SessionState::RadiusFrameReceived, "frame_rcvd") {
            emit_metric(&metrics_tx, MetricSample::StateViolation);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }

        debug!(
            action = "packet_received",
            session_id = tracker.session_id(),
            size = length,
            peer_fp = %peer_identity.fingerprint_sha256_hex,
            "Successfully framed RadSec packet"
        );

        let outcome = process_radius_packet(
            &full_packet,
            &cfg,
            &kanidm,
            tracker.session_id(),
            &control_tx,
            &metrics_tx,
        ).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if let Err(e) = tracker.transition(SessionState::RadiusValidated, "radius_validated") {
            emit_metric(&metrics_tx, MetricSample::StateViolation);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }

        match outcome.observed_eap_type {
            Some(EAP_TYPE_IDENTITY) => {
                if let Err(e) = tracker.transition(SessionState::EapIdentityObserved, "eap_identity") {
                    emit_metric(&metrics_tx, MetricSample::StateViolation);
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
                }
            }
            Some(EAP_TYPE_TLS) => {
                if let Err(e) = tracker.transition(SessionState::EapTlsObserved, "eap_tls") {
                    emit_metric(&metrics_tx, MetricSample::StateViolation);
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
                }
            }
            _ => {
                // Local reject path may not have a typed EAP outcome.
            }
        }

        if let Err(e) = tracker.transition(SessionState::UpstreamPending, "awaiting_upstream_or_local_decision") {
            emit_metric(&metrics_tx, MetricSample::StateViolation);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }

        match outcome.result_state {
            ProcessResultState::Challenge => {
                let _ = tracker.transition(SessionState::UpstreamChallengeRelayed, "challenge_relayed");
            }
            ProcessResultState::Accept => {
                let _ = tracker.transition(SessionState::UpstreamAcceptRelayed, "accept_relayed");
            }
            ProcessResultState::Reject => {
                let _ = tracker.transition(SessionState::UpstreamRejectRelayed, "reject_relayed");
            }
        }

        timeout(io_timeout, stream.write_all(&outcome.response)).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out writing response"))??;
        timeout(io_timeout, stream.flush()).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out flushing response"))??;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ProcessResultState {
    Challenge,
    Accept,
    Reject,
}

#[derive(Debug, Clone)]
struct ProcessOutcome {
    response: Vec<u8>,
    result_state: ProcessResultState,
    observed_eap_type: Option<u8>,
}

async fn process_radius_packet(
    request_bytes: &[u8],
    cfg: &Config,
    kanidm: &KanidmRadiusClient,
    session_id: u64,
    control_tx: &Option<ControlTx>,
    metrics_tx: &Option<MetricsTx>,
) -> Result<ProcessOutcome, String> {
    let request = RadiusPacket::parse(request_bytes, cfg.radius.max_packet_size)?;

    if let Some(tx) = control_tx {
        let _ = tx.try_send(ControlEvent::RadiusObserved {
            session_id,
            radius_id: request.identifier,
            code: request.code,
            packet_len: request_bytes.len(),
        });
    }

    if request.code != CODE_ACCESS_REQUEST {
        emit_metric(metrics_tx, MetricSample::Reject("reject_policy"));
        return Err(format!(
            "Unsupported RADIUS code {}: only Access-Request is accepted",
            request.code
        ));
    }

    if cfg.radius.require_message_authenticator {
        if let Err(e) = request.verify_request_message_authenticator(cfg.radius.shared_secret.as_bytes()) {
            emit_metric(metrics_tx, MetricSample::Reject("reject_policy"));
            if let Some(tx) = control_tx {
                let _ = tx.try_send(ControlEvent::RejectReason {
                    session_id,
                    radius_id: Some(request.identifier),
                    reason: format!("message_authenticator_invalid: {}", e),
                });
            }
            return Err(e);
        }
    }

    if !request.has_attribute(ATTR_EAP_MESSAGE) {
        emit_metric(metrics_tx, MetricSample::Reject("reject_eap"));
        if let Some(tx) = control_tx {
            let _ = tx.try_send(ControlEvent::RejectReason {
                session_id,
                radius_id: Some(request.identifier),
                reason: "missing_eap_message".to_string(),
            });
        }
        return Err("Missing EAP-Message in Access-Request".to_string());
    }

    let parsed_meta = parse_eap_message(&request.attributes)?;
    if let Some(tx) = control_tx {
        let _ = tx.try_send(ControlEvent::EapObserved {
            session_id,
            radius_id: request.identifier,
            eap_id: parsed_meta.identifier,
            eap_type: parsed_meta.eap_type,
        });
    }

    let eap_meta = match enforce_eap_tls_only(&request.attributes) {
        Ok(meta) => meta,
        Err(reason) => {
            emit_metric(metrics_tx, MetricSample::Reject("reject_eap"));
            if let Some(tx) = control_tx {
                let _ = tx.try_send(ControlEvent::RejectReason {
                    session_id,
                    radius_id: Some(request.identifier),
                    reason: reason.clone(),
                });
            }
            let response = RadiusPacket::build_access_reject_with_eap_failure(
                &request,
                parsed_meta.identifier,
                cfg.radius.shared_secret.as_bytes(),
            )?;
            return Ok(ProcessOutcome {
                response,
                result_state: ProcessResultState::Reject,
                observed_eap_type: parsed_meta.eap_type,
            });
        }
    };

    debug!(
        action = "eap_request",
        session_id = session_id,
        radius_id = request.identifier,
        eap_id = eap_meta.identifier,
        eap_type = ?eap_meta.eap_type,
        "Validated incoming EAP request"
    );

    let upstream_start = Instant::now();
    let upstream_response = match kanidm.exchange(request_bytes).await {
        Ok(resp) => resp,
        Err(e) => {
            emit_metric(metrics_tx, MetricSample::Reject("reject_upstream"));
            if let Some(tx) = control_tx {
                let _ = tx.try_send(ControlEvent::RejectReason {
                    session_id,
                    radius_id: Some(request.identifier),
                    reason: format!("upstream_exchange_failed: {}", e),
                });
            }
            let response = RadiusPacket::build_access_reject_with_eap_failure(
                &request,
                eap_meta.identifier,
                cfg.radius.shared_secret.as_bytes(),
            )?;
            return Ok(ProcessOutcome {
                response,
                result_state: ProcessResultState::Reject,
                observed_eap_type: eap_meta.eap_type,
            });
        }
    };
    let upstream_rtt_ms = upstream_start.elapsed().as_millis() as u64;
    emit_metric(metrics_tx, MetricSample::UpstreamRttMs(upstream_rtt_ms));

    if let Err(e) = RadiusPacket::verify_response_authenticator(
        &upstream_response,
        request.authenticator,
        cfg.radius.shared_secret.as_bytes(),
    ) {
        emit_metric(metrics_tx, MetricSample::Reject("reject_upstream"));
        if let Some(tx) = control_tx {
            let _ = tx.try_send(ControlEvent::RejectReason {
                session_id,
                radius_id: Some(request.identifier),
                reason: format!("upstream_response_authenticator_invalid: {}", e),
            });
        }
        return Err(e);
    }

    let parsed_response = RadiusPacket::parse(&upstream_response, cfg.radius.max_packet_size)?;

    let result_state = match parsed_response.code {
        CODE_ACCESS_CHALLENGE => ProcessResultState::Challenge,
        CODE_ACCESS_ACCEPT => ProcessResultState::Accept,
        CODE_ACCESS_REJECT => ProcessResultState::Reject,
        other => {
            emit_metric(metrics_tx, MetricSample::Reject("reject_upstream"));
            return Err(format!(
                "Upstream Kanidm returned unsupported response code {}",
                other
            ));
        }
    };

    Ok(ProcessOutcome {
        response: upstream_response,
        result_state,
        observed_eap_type: eap_meta.eap_type,
    })
}

fn emit_metric(metrics_tx: &Option<MetricsTx>, sample: MetricSample) {
    if let Some(tx) = metrics_tx {
        if tx.try_send(sample).is_err() {
            let _ = tx.try_send(MetricSample::QueueDrop("queue_drop_metrics"));
        }
    }
}
