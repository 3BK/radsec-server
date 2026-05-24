use radsec_server::{config, crypto, server};
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize JSONL Audit Logging (PCI DSS Req 10, NIST AU-2)
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_max_level(Level::INFO)
        .init();

    info!(action = "server_start", status = "initializing", "Starting Production Secure RadSec Server");

    // 2. Load TOML Configuration
    let config_path = std::env::var("RADSEC_CONFIG").unwrap_or_else(|_| "/etc/radsec/config.toml".to_string());
    let cfg = config::load_config(&config_path)?;

    // 3. Verify Local File Permissions (STIG / PCI DSS Constraint)
    // Ensures the private key is heavily restricted (e.g., 0400 or 0600)
    config::verify_file_permissions(&cfg.tls.private_key_path)?;

    // 4. Configure TLS 1.3, PQ, and mTLS (P-384)
    let tls_config = crypto::build_tls_config(&cfg.tls)?;

    // 5. Run Server with Graceful Shutdown
    server::run(cfg.server, tls_config).await?;

    Ok(())
}
