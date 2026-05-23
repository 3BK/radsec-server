use crate::config::TlsConfig;
use rustls::pki_types::CertificateDer; // Removed unused PrivateKeyDer
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;

pub fn build_tls_config(tls_cfg: &TlsConfig) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // 1. Load Client CA (mTLS Requirement)
    let mut ca_roots = RootCertStore::empty();
    let ca_file = fs::File::open(&tls_cfg.client_ca_path)?;
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca_file)) {
        ca_roots.add(cert?)?;
    }
    
    // Require valid client certificates (mTLS)
    let client_auth = WebPkiClientVerifier::builder(Arc::new(ca_roots)).build()?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();

    // Store the builder temporarily
    let builder = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_auth);

    // 2. Load Server Cert
    let cert_file = fs::File::open(&tls_cfg.server_cert_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .map(|r| r.unwrap())
        .collect();

    // 3. Load Private Key
    let key_file = fs::File::open(&tls_cfg.private_key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("No private key found")?;

    // 4. Finalize the configuration (consumes the builder, returns ServerConfig)
    let mut server_config = builder.with_single_cert(certs, key)?;
    
    // 5. Append RadSec ALPN to the finalized config
    server_config.alpn_protocols.push(b"radius".to_vec());

    Ok(server_config)
}
