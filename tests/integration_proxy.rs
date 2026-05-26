use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use radsec_server::config::UpstreamConfig;
use radsec_server::kanidm::KanidmRadiusClient;
use radsec_server::radius::{
    RadiusAttribute, RadiusPacket, ATTR_EAP_MESSAGE, ATTR_MESSAGE_AUTHENTICATOR,
    CODE_ACCESS_ACCEPT, CODE_ACCESS_CHALLENGE, CODE_ACCESS_REQUEST, CODE_ACCESS_REJECT,
};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

type HmacMd5 = Hmac<Md5>;

fn build_eap_response(eap_type: u8, identifier: u8, body: &[u8]) -> Vec<u8> {
    let total_len = 5 + body.len();
    let mut out = Vec::with_capacity(total_len);
    out.push(2u8); // EAP-Response
    out.push(identifier);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.push(eap_type);
    out.extend_from_slice(body);
    out
}

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

fn build_response_from_request(
    request: &RadiusPacket,
    code: u8,
    attrs: Vec<RadiusAttribute>,
    shared_secret: &[u8],
) -> Vec<u8> {
    let mut resp = RadiusPacket {
        code,
        identifier: request.identifier,
        authenticator: [0u8; 16],
        attributes: attrs,
    };

    let mut bytes = resp.to_bytes().expect("response should serialize");

    let mut material = Vec::with_capacity(bytes.len() + shared_secret.len());
    material.push(resp.code);
    material.push(resp.identifier);
    material.extend_from_slice(&bytes[2..4]);
    material.extend_from_slice(&request.authenticator);
    material.extend_from_slice(&bytes[20..]);
    material.extend_from_slice(shared_secret);

    let digest = Md5::digest(&material);
    resp.authenticator.copy_from_slice(&digest);
    bytes[4..20].copy_from_slice(&digest);

    bytes
}

async fn spawn_mock_radius_backend_once<F>(handler: F) -> std::net::SocketAddr
where
    F: Fn(RadiusPacket, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind mock backend");
    let addr = socket.local_addr().expect("local addr");

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = socket.recv_from(&mut buf).await.expect("recv request");
        buf.truncate(n);

        let request = RadiusPacket::parse(&buf, 4096).expect("request should parse");
        let response = handler(request, buf);

        socket
            .send_to(&response, peer)
            .await
            .expect("send response");
    });

    addr
}

#[tokio::test]
async fn upstream_proxy_round_trip_access_challenge() {
    let secret = b"radsec";
    let request_bytes =
        build_access_request_with_eap(build_eap_response(13, 0x11, &[0x80, 0x00]), secret);

    let upstream_addr = spawn_mock_radius_backend_once(move |request, _raw| {
        let challenge_eap = vec![1u8, 0x11, 0x00, 0x06, 13u8, 0x20]; // EAP-Request/TLS-like stub
        build_response_from_request(
            &request,
            CODE_ACCESS_CHALLENGE,
            vec![RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: challenge_eap,
            }],
            secret,
        )
    })
    .await;

    let client = KanidmRadiusClient::new(
        &UpstreamConfig {
            address: upstream_addr.to_string(),
            timeout_secs: 2,
        },
        4096,
    )
    .expect("client");

    let response = client.exchange(&request_bytes).await.expect("exchange");
    let request = RadiusPacket::parse(&request_bytes, 4096).expect("request parse");

    RadiusPacket::verify_response_authenticator(
        &response,
        request.authenticator,
        secret,
    )
    .expect("response authenticator should validate");

    let parsed = RadiusPacket::parse(&response, 4096).expect("response parse");
    assert_eq!(parsed.code, CODE_ACCESS_CHALLENGE);
    assert_eq!(parsed.identifier, request.identifier);
    assert!(parsed.has_attribute(ATTR_EAP_MESSAGE));
}

#[tokio::test]
async fn upstream_proxy_round_trip_access_accept() {
    let secret = b"radsec";
    let request_bytes =
        build_access_request_with_eap(build_eap_response(13, 0x44, &[0x00, 0x01, 0x02]), secret);

    let upstream_addr = spawn_mock_radius_backend_once(move |request, _raw| {
        build_response_from_request(
            &request,
            CODE_ACCESS_ACCEPT,
            vec![
                RadiusAttribute {
                    typ: 64, // Tunnel-Type
                    value: vec![0x00, 0x00, 0x00, 0x0d],
                },
                RadiusAttribute {
                    typ: 81, // Tunnel-Private-Group-Id
                    value: b"100".to_vec(),
                },
            ],
            secret,
        )
    })
    .await;

    let client = KanidmRadiusClient::new(
        &UpstreamConfig {
            address: upstream_addr.to_string(),
            timeout_secs: 2,
        },
        4096,
    )
    .expect("client");

    let response = client.exchange(&request_bytes).await.expect("exchange");
    let request = RadiusPacket::parse(&request_bytes, 4096).expect("request parse");

    RadiusPacket::verify_response_authenticator(
        &response,
        request.authenticator,
        secret,
    )
    .expect("response authenticator should validate");

    let parsed = RadiusPacket::parse(&response, 4096).expect("response parse");
    assert_eq!(parsed.code, CODE_ACCESS_ACCEPT);
    assert_eq!(parsed.identifier, request.identifier);
}

#[tokio::test]
async fn upstream_proxy_round_trip_access_reject() {
    let secret = b"radsec";
    let request_bytes =
        build_access_request_with_eap(build_eap_response(13, 0x55, &[0x80]), secret);

    let upstream_addr = spawn_mock_radius_backend_once(move |request, _raw| {
        build_response_from_request(&request, CODE_ACCESS_REJECT, vec![], secret)
    })
    .await;

    let client = KanidmRadiusClient::new(
        &UpstreamConfig {
            address: upstream_addr.to_string(),
            timeout_secs: 2,
        },
        4096,
    )
    .expect("client");

    let response = client.exchange(&request_bytes).await.expect("exchange");
    let request = RadiusPacket::parse(&request_bytes, 4096).expect("request parse");

    RadiusPacket::verify_response_authenticator(
        &response,
        request.authenticator,
        secret,
    )
    .expect("response authenticator should validate");

    let parsed = RadiusPacket::parse(&response, 4096).expect("response parse");
    assert_eq!(parsed.code, CODE_ACCESS_REJECT);
    assert_eq!(parsed.identifier, request.identifier);
}

#[tokio::test]
async fn upstream_proxy_timeout_is_reported_to_caller() {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind blackhole");
    let addr = socket.local_addr().expect("local addr");

    // Intentionally never respond.
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let _ = socket.recv_from(&mut buf).await;
        sleep(Duration::from_secs(3)).await;
    });

    let client = KanidmRadiusClient::new(
        &UpstreamConfig {
            address: addr.to_string(),
            timeout_secs: 1,
        },
        4096,
    )
    .expect("client");

    let request_bytes =
        build_access_request_with_eap(build_eap_response(13, 0x66, &[0x80, 0x00]), b"radsec");

    let err = client
        .exchange(&request_bytes)
        .await
        .expect_err("timeout expected");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("elapsed") || msg.contains("timed out") || msg.contains("deadline"),
        "unexpected timeout error: {msg}"
    );
}
