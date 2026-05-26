use crate::eap::enforce_eap_tls_only;
use crate::radius::RadiusPacket;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub enum ControlEvent {
    SessionOpened {
        session_id: u64,
        source_ip: std::net::IpAddr,
    },
    StateTransition {
        session_id: u64,
        from: crate::state::SessionState,
        to: crate::state::SessionState,
        reason: &'static str,
    },
    PeerIdentity {
        session_id: u64,
        fingerprint_sha256: String,
        subject_cn: Option<String>,
        san_uris: Vec<String>,
        san_dns: Vec<String>,
    },
    RadiusObserved {
        session_id: u64,
        radius_id: u8,
        code: u8,
        packet_len: usize,
    },
    EapObserved {
        session_id: u64,
        radius_id: u8,
        eap_id: u8,
        eap_type: Option<u8>,
    },
    RejectReason {
        session_id: u64,
        radius_id: Option<u8>,
        reason: String,
    },
    ShadowVerdict {
        session_id: u64,
        packet_sha256: String,
        accepted: bool,
        reason: String,
    },
    SessionClosed {
        session_id: u64,
    },
}

#[derive(Debug, Clone)]
pub struct ShadowWork {
    pub session_id: u64,
    pub packet: Vec<u8>,
    pub max_packet_size: usize,
    pub require_message_authenticator: bool,
    pub shared_secret: String,
    pub enforce_eap_tls_only: bool,
}

pub type ControlTx = mpsc::Sender<ControlEvent>;
pub type ControlRx = mpsc::Receiver<ControlEvent>;
pub type ShadowTx = mpsc::Sender<ShadowWork>;
pub type ShadowRx = mpsc::Receiver<ShadowWork>;

pub fn spawn_control_event_drain(mut rx: ControlRx) {
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            debug!(action = "control_event", "Control-plane event: {event:?}");
        }
    });
}

pub fn spawn_shadow_actor(mut rx: ShadowRx, control_tx: Option<ControlTx>) {
    tokio::spawn(async move {
        while let Some(work) = rx.recv().await {
            let mut h = Sha256::new();
            h.update(&work.packet);
            let packet_sha256 = hex::encode(h.finalize());

            let verdict = match RadiusPacket::parse(&work.packet, work.max_packet_size) {
                Ok(pkt) => {
                    if work.require_message_authenticator {
                        if let Err(e) =
                            pkt.verify_request_message_authenticator(work.shared_secret.as_bytes())
                        {
                            (false, format!("shadow_msg_auth_fail: {e}"))
                        } else if work.enforce_eap_tls_only {
                            match enforce_eap_tls_only(&pkt.attributes) {
                                Ok(_) => (true, "shadow_ok".to_string()),
                                Err(e) => (false, format!("shadow_eap_fail: {e}")),
                            }
                        } else {
                            (false, "shadow_mode_without_eap_tls_only_disabled".to_string())
                        }
                    } else if work.enforce_eap_tls_only {
                        match enforce_eap_tls_only(&pkt.attributes) {
                            Ok(_) => (true, "shadow_ok".to_string()),
                            Err(e) => (false, format!("shadow_eap_fail: {e}")),
                        }
                    } else {
                        (false, "shadow_mode_without_eap_tls_only_disabled".to_string())
                    }
                }
                Err(e) => (false, format!("shadow_parse_fail: {e}")),
            };

            if let Some(tx) = &control_tx {
                let _ = tx.try_send(ControlEvent::ShadowVerdict {
                    session_id: work.session_id,
                    packet_sha256,
                    accepted: verdict.0,
                    reason: verdict.1,
                });
            } else if !verdict.0 {
                warn!(
                    action = "shadow_verdict",
                    session_id = work.session_id,
                    accepted = verdict.0,
                    reason = %verdict.1,
                    "Shadow validator observed failure"
                );
            }
        }
    });
}
