use kanidm_radsec_edge::{config, crypto, server};
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_max_level(Level::INFO)
        .init();

    info!(
        action = "server_start",
        status = "initializing",
        mode = "radsec_edge_proxy",
        eap_mode = "eap-tls-only",
        ndt = "internal-shadow-only",
        metrology = "internal-bounded-queue",
        "Starting secure Kanidm-aware RadSec edge"
    );

    let config_path =
        std::env::var("RADSEC_CONFIG").unwrap_or_else(|_| "/etc/radsec/config.toml".to_string());

    let cfg = config::load_config(&config_path)?;
    config::verify_file_permissions(&cfg.tls.private_key_path)?;

    let tls_config = crypto::build_tls_config(&cfg.tls)?;
    server::run(cfg, tls_config).await?;

    Ok(())
}
