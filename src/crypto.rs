use crate::config::TlsConfig;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;
use zeroize::Zeroize;

pub fn build_tls_config(tls_cfg: &TlsConfig) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // 1. Load Client CA (mTLS Requirement)
    let mut ca_roots = RootCertStore::empty();
    let ca_bytes = fs::read(&tls_cfg.client_ca_path)?;
    for p in pem::parse_many(&ca_bytes)? {
        if p.tag() == "CERTIFICATE" {
            ca_roots.add(CertificateDer::from(p.contents().to_vec()))?;
        }
    }

    // Require valid client certificates (mTLS)
    let client_auth = WebPkiClientVerifier::builder(Arc::new(ca_roots)).build()?;

    // 2. Strict Cryptographic Enforcement (NIST / PCI DSS 4.0)
    let mut provider = aws_lc_rs::default_provider();

    // Force strictly SECP384R1 (P-384) for Key Exchange
    provider.kx_exts = vec![aws_lc_rs::kx_group::SECP384R1];

    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        // Strictly require TLS 1.3 (Drops TLS 1.2 to meet highest compliance)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_auth);

    // 3. Load Server Certs
    let cert_bytes = fs::read(&tls_cfg.server_cert_path)?;
    let certs: Vec<CertificateDer<'static>> = pem::parse_many(&cert_bytes)?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.contents().to_vec()))
        .collect();

    if certs.is_empty() {
        return Err("No valid certificates found in server_cert_path".into());
    }

    // 4. Load Private Key with Memory Hygiene (Zeroize)
    let mut key_bytes = fs::read(&tls_cfg.private_key_path)?;
    let key_pem = pem::parse(&key_bytes)?;

    // Map the PEM tag to the strict PKI types required by Rustls
    let key = match key_pem.tag() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem.contents().to_vec())),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key_pem.contents().to_vec())),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key_pem.contents().to_vec())),
        _ => return Err(format!("Unsupported private key format: {}", key_pem.tag()).into()),
    };

    // Zeroize the raw bytes from memory immediately after parsing
    key_bytes.zeroize();

    // 5. Finalize the configuration
    let mut server_config = builder.with_single_cert(certs, key)?;
    
    // Enforce ALPN negotiation for RadSec (RFC 6614)
    server_config.alpn_protocols = vec![b"radius".to_vec()];

    Ok(server_config)
}
