use hmac::{Hmac, Mac};
use md5::Md5;
use radsec_server::config::{load_config, verify_file_permissions};
use radsec_server::control::{spawn_shadow_actor, ControlEvent, ShadowWork};
use radsec_server::crypto::{verify_peer_identity, PeerIdentity};
use radsec_server::eap::{
    enforce_eap_tls_only, parse_eap_message, EAP_CODE_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_TLS,
};
use radsec_server::metrics::MetricSample;
use radsec_server::radius::{
    RadiusAttribute, RadiusPacket, ATTR_EAP_MESSAGE, ATTR_MESSAGE_AUTHENTICATOR,
    CODE_ACCESS_REQUEST, CODE_ACCESS_REJECT,
};
use radsec_server::state::{can_transition, SessionState, SessionTracker};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use tokio::sync::mpsc;

type HmacMd5 = Hmac<Md5>;

fn build_access_request_with_eap(eap_payload: Vec<u8>, shared_secret: &[u8]) -> Vec<u8> {
    let mut pkt = RadiusPacket {
        code: CODE_ACCESS_REQUEST,
        identifier: 7,
        authenticator: [
            0x10, 0x11, 0x12, 0x13, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42,
            0x43, 0x44,
        ],
        attributes: vec![
            RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: eap_payload,
            },
            RadiusAttribute {
                typ: ATTR_MESSAGE_AUTHENTICATOR,
                value: vec![0u8; 16],
            },
        ],
    };

    let zeroed = pkt.with_zeroed_message_authenticator();
    let bytes = zeroed.to_bytes().expect("zeroed packet should serialize");

    let mut mac = HmacMd5::new_from_slice(shared_secret).expect("valid hmac key");
    mac.update(&bytes);
    let digest = mac.finalize().into_bytes();

    for attr in &mut pkt.attributes {
        if attr.typ == ATTR_MESSAGE_AUTHENTICATOR {
            attr.value = digest.to_vec();
        }
    }

    pkt.to_bytes().expect("final packet should serialize")
}

fn build_eap_response(eap_type: u8, identifier: u8, body: &[u8]) -> Vec<u8> {
    let total_len = 5 + body.len();
    let mut out = Vec::with_capacity(total_len);
    out.push(EAP_CODE_RESPONSE);
    out.push(identifier);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.push(eap_type);
    out.extend_from_slice(body);
    out
}

#[test]
fn verify_file_permissions_accepts_0400_and_rejects_loose_modes() {
    let dir = tempdir().expect("tempdir");
    let key_path = dir.path().join("server.key");
    fs::write(&key_path, b"dummy-key").expect("write key");

    let mut perms = fs::metadata(&key_path).expect("metadata").permissions();
    perms.set_mode(0o400);
    fs::set_permissions(&key_path, perms).expect("chmod 0400");
    verify_file_permissions(key_path.to_str().unwrap()).expect("0400 should be accepted");

    let mut perms = fs::metadata(&key_path).expect("metadata").permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&key_path, perms).expect("chmod 0644");
    assert!(
        verify_file_permissions(key_path.to_str().unwrap()).is_err(),
        "0644 must be rejected"
    );
}

#[test]
fn load_config_parses_full_secure_config() {
    let dir = tempdir().expect("tempdir");
    let cfg_path = dir.path().join("config.toml");

    let toml = r#"
[server]
bind_address = "0.0.0.0:2083"
max_connections_per_sec = 100
handshake_timeout_secs = 10
io_timeout_secs = 30
shutdown_grace_secs = 10

[tls]
client_ca_path = "/etc/radsec/client_ca.pem"
server_cert_path = "/etc/radsec/server.pem"
private_key_path = "/etc/radsec/server.key"
require_alpn_radius = false

[peer_policy]
allowed_sha256_fingerprints = []
require_san_uri_prefix = null
require_san_dns_suffix = ".example.net"
allow_subject_cn_fallback = false

[radius]
shared_secret = "radsec"
require_message_authenticator = true
max_packet_size = 4096

[upstream]
address = "127.0.0.1:1812"
timeout_secs = 5

[eap]
enforce_eap_tls_only = true

[control_plane]
enabled = true
queue_capacity = 1024
shadow_queue_capacity = 512
shadow_mode = true
allow_fault_injection = false
queue_drop_log_interval_secs = 60

[metrology]
enabled = true
queue_capacity = 2048
flush_interval_secs = 30
"#;

    fs::write(&cfg_path, toml).expect("write config");
    let cfg = load_config(cfg_path.to_str().unwrap()).expect("config should parse");

    assert_eq!(cfg.server.bind_address, "0.0.0.0:2083");
    assert_eq!(cfg.server.max_connections_per_sec, 100);
    assert_eq!(cfg.tls.client_ca_path, "/etc/radsec/client_ca.pem");
    assert_eq!(cfg.radius.shared_secret, "radsec");
    assert!(cfg.radius.require_message_authenticator);
    assert!(cfg.eap.enforce_eap_tls_only);
    assert!(cfg.control_plane.enabled);
    assert!(cfg.control_plane.shadow_mode);
    assert!(!cfg.control_plane.allow_fault_injection);
    assert!(cfg.metrology.enabled);
}

#[test]
fn radius_packet_roundtrip_and_message_authenticator_verify() {
    let secret = b"radsec";
    let eap = build_eap_response(EAP_TYPE_TLS, 9, &[0x80, 0x00, 0x01]);
    let bytes = build_access_request_with_eap(eap, secret);

    let parsed = RadiusPacket::parse(&bytes, 4096).expect("packet should parse");
    assert_eq!(parsed.code, CODE_ACCESS_REQUEST);
    assert!(parsed.has_attribute(ATTR_EAP_MESSAGE));
    assert!(parsed.has_attribute(ATTR_MESSAGE_AUTHENTICATOR));

    parsed
        .verify_request_message_authenticator(secret)
        .expect("Message-Authenticator should validate");
}

#[test]
fn radius_message_authenticator_detects_tampering() {
    let secret = b"radsec";
    let eap = build_eap_response(EAP_TYPE_TLS, 3, &[0x01, 0x02, 0x03]);
    let mut bytes = build_access_request_with_eap(eap, secret);

    let last = bytes.last_mut().expect("non-empty");
    *last ^= 0xFF;

    let parsed = RadiusPacket::parse(&bytes, 4096).expect("tampered packet still parses");
    assert!(
        parsed.verify_request_message_authenticator(secret).is_err(),
        "tampering must invalidate Message-Authenticator"
    );
}

#[test]
fn eap_tls_only_allows_identity_and_tls_and_rejects_other_methods() {
    let identity = build_eap_response(EAP_TYPE_IDENTITY, 1, b"user@example.net");
    let tls = build_eap_response(EAP_TYPE_TLS, 2, &[0x80, 0x00]);
    let peap_like = build_eap_response(25, 3, &[0x00]);

    let identity_attrs = vec![RadiusAttribute {
        typ: ATTR_EAP_MESSAGE,
        value: identity,
    }];
    let tls_attrs = vec![RadiusAttribute {
        typ: ATTR_EAP_MESSAGE,
        value: tls,
    }];
    let peap_attrs = vec![RadiusAttribute {
        typ: ATTR_EAP_MESSAGE,
        value: peap_like,
    }];

    let meta_identity = enforce_eap_tls_only(&identity_attrs).expect("identity should pass");
    assert_eq!(meta_identity.eap_type, Some(EAP_TYPE_IDENTITY));

    let meta_tls = enforce_eap_tls_only(&tls_attrs).expect("eap-tls should pass");
    assert_eq!(meta_tls.eap_type, Some(EAP_TYPE_TLS));

    let err = enforce_eap_tls_only(&peap_attrs).expect_err("non-EAP-TLS must fail");
    assert!(
        err.contains("Unsupported EAP method"),
        "unexpected reject reason: {err}"
    );
}

#[test]
fn parse_eap_message_extracts_identifier_and_type() {
    let tls = build_eap_response(EAP_TYPE_TLS, 0x2A, &[0x80]);
    let attrs = vec![RadiusAttribute {
        typ: ATTR_EAP_MESSAGE,
        value: tls,
    }];

    let meta = parse_eap_message(&attrs).expect("EAP should parse");
    assert_eq!(meta.code, EAP_CODE_RESPONSE);
    assert_eq!(meta.identifier, 0x2A);
    assert_eq!(meta.eap_type, Some(EAP_TYPE_TLS));
}

#[test]
fn access_reject_with_eap_failure_is_well_formed() {
    let secret = b"radsec";
    let eap = build_eap_response(EAP_TYPE_TLS, 0x19, &[0x80, 0x00]);
    let request_bytes = build_access_request_with_eap(eap, secret);
    let request = RadiusPacket::parse(&request_bytes, 4096).expect("request parse");

    let reject = RadiusPacket::build_access_reject_with_eap_failure(&request, 0x19, secret)
        .expect("reject builder");

    let parsed = RadiusPacket::parse(&reject, 4096).expect("reject parse");
    assert_eq!(parsed.code, CODE_ACCESS_REJECT);
    assert_eq!(parsed.identifier, request.identifier);

    let eap_attr = parsed
        .attributes
        .iter()
        .find(|a| a.typ == ATTR_EAP_MESSAGE)
        .expect("EAP-Message on reject");

    assert_eq!(eap_attr.value, vec![4u8, 0x19, 0x00, 0x04]); // EAP-Failure
}

#[test]
fn peer_policy_accepts_matching_fingerprint_and_san_and_rejects_mismatch() {
    let peer = PeerIdentity {
        fingerprint_sha256_hex: "abc123".to_string(),
        subject_cn: Some("radsec-edge-01".to_string()),
        san_uris: vec!["spiffe://region.example.net/radsec/ap01".to_string()],
        san_dns: vec!["ap01.wifi.example.net".to_string()],
    };

    let good_policy = radsec_server::config::PeerPolicyConfig {
        allowed_sha256_fingerprints: vec!["abc123".to_string()],
        require_san_uri_prefix: Some("spiffe://region.example.net/radsec/".to_string()),
        require_san_dns_suffix: Some(".wifi.example.net".to_string()),
        allow_subject_cn_fallback: false,
    };

    verify_peer_identity(&peer, &good_policy).expect("peer should satisfy policy");

    let bad_policy = radsec_server::config::PeerPolicyConfig {
        allowed_sha256_fingerprints: vec!["deadbeef".to_string()],
        require_san_uri_prefix: Some("spiffe://region.example.net/radsec/".to_string()),
        require_san_dns_suffix: Some(".wifi.example.net".to_string()),
        allow_subject_cn_fallback: false,
    };

    assert!(
        verify_peer_identity(&peer, &bad_policy).is_err(),
        "fingerprint mismatch must fail"
    );
}

#[test]
fn state_machine_allows_expected_transitions_and_blocks_illegal_ones() {
    assert!(can_transition(
        SessionState::AcceptedTcp,
        SessionState::TlsHandshakeStarted
    ));
    assert!(can_transition(
        SessionState::TlsHandshakeStarted,
        SessionState::TlsEstablished
    ));
    assert!(can_transition(
        SessionState::RadiusValidated,
        SessionState::EapTlsObserved
    ));
    assert!(!can_transition(
        SessionState::AcceptedTcp,
        SessionState::UpstreamPending
    ));
    assert!(!can_transition(
        SessionState::TlsEstablished,
        SessionState::UpstreamAcceptRelayed
    ));
}

#[tokio::test]
async fn session_tracker_emits_state_violation_on_illegal_transition_path() {
    let (control_tx, mut control_rx) = mpsc::channel(16);
    let (metrics_tx, mut metrics_rx) = mpsc::channel(16);

    let mut tracker = SessionTracker::new(42, Some(control_tx), Some(metrics_tx));

    tracker
        .transition(SessionState::TlsHandshakeStarted, "tcp_accepted")
        .expect("first transition should pass");

    let illegal = tracker.transition(SessionState::UpstreamPending, "jump_ahead");
    assert!(illegal.is_err(), "illegal transition must fail");

    // We should at least observe the valid first transition event.
    let first = control_rx.recv().await.expect("control event");
    match first {
        ControlEvent::StateTransition { session_id, from, to, .. } => {
            assert_eq!(session_id, 42);
            assert_eq!(from, SessionState::AcceptedTcp);
            assert_eq!(to, SessionState::TlsHandshakeStarted);
        }
        other => panic!("unexpected control event: {other:?}"),
    }

    let metric = metrics_rx.recv().await.expect("metric sample");
    match metric {
        MetricSample::StateViolation => {}
        other => panic!("expected StateViolation metric, got {other:?}"),
    }
}

#[tokio::test]
async fn shadow_actor_reports_non_eap_tls_request_as_rejected_without_touching_live_path() {
    let (control_tx, mut control_rx) = mpsc::channel(16);
    let (shadow_tx, shadow_rx) = mpsc::channel(16);

    spawn_shadow_actor(shadow_rx, Some(control_tx));

    let secret = "radsec".to_string();
    let non_tls_eap = build_eap_response(25, 0x33, &[0x00]); // e.g. PEAP-like / unsupported
    let packet = build_access_request_with_eap(non_tls_eap, secret.as_bytes());

    shadow_tx
        .send(ShadowWork {
            session_id: 9001,
            packet: packet.clone(),
            max_packet_size: 4096,
            require_message_authenticator: true,
            shared_secret: secret,
            enforce_eap_tls_only: true,
        })
        .await
        .expect("shadow send");

    let event = control_rx.recv().await.expect("shadow verdict");
    match event {
        ControlEvent::ShadowVerdict {
            session_id,
            packet_sha256,
            accepted,
            reason,
        } => {
            assert_eq!(session_id, 9001);
            assert!(!accepted, "unsupported EAP method must be rejected in shadow mode");
            assert!(
                reason.contains("shadow_eap_fail"),
                "unexpected reason: {reason}"
            );

            let mut h = sha2::Sha256::new();
            h.update(&packet);
            let expected = hex::encode(h.finalize());
            assert_eq!(packet_sha256, expected);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}
