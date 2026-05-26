use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub peer_policy: PeerPolicyConfig,
    pub radius: RadiusConfig,
    pub upstream: UpstreamConfig,
    pub eap: EapConfig,
    pub control_plane: ControlPlaneConfig,
    pub metrology: MetrologyConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub max_connections_per_sec: u32,
    pub handshake_timeout_secs: u64,
    pub io_timeout_secs: u64,
    pub shutdown_grace_secs: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TlsConfig {
    pub client_ca_path: String,
    pub server_cert_path: String,
    pub private_key_path: String,
    #[serde(default)]
    pub require_alpn_radius: bool,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct PeerPolicyConfig {
    #[serde(default)]
    pub allowed_sha256_fingerprints: Vec<String>,

    pub require_san_uri_prefix: Option<String>,
    pub require_san_dns_suffix: Option<String>,

    #[serde(default = "default_allow_subject_cn_fallback")]
    pub allow_subject_cn_fallback: bool,
}

fn default_allow_subject_cn_fallback() -> bool {
    false
}

#[derive(Deserialize, Debug, Clone)]
pub struct RadiusConfig {
    #[serde(default = "default_radius_shared_secret")]
    pub shared_secret: String,
    #[serde(default = "default_require_message_authenticator")]
    pub require_message_authenticator: bool,
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,
}

fn default_radius_shared_secret() -> String {
    "radsec".to_string()
}

fn default_require_message_authenticator() -> bool {
    true
}

fn default_max_packet_size() -> usize {
    4096
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpstreamConfig {
    pub address: String,
    pub timeout_secs: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct EapConfig {
    #[serde(default = "default_enforce_eap_tls_only")]
    pub enforce_eap_tls_only: bool,
}

fn default_enforce_eap_tls_only() -> bool {
    true
}

#[derive(Deserialize, Debug, Clone)]
pub struct ControlPlaneConfig {
    #[serde(default = "default_cp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cp_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_cp_shadow_queue_capacity")]
    pub shadow_queue_capacity: usize,
    #[serde(default = "default_cp_shadow_mode")]
    pub shadow_mode: bool,
    #[serde(default = "default_cp_allow_fault_injection")]
    pub allow_fault_injection: bool,
    #[serde(default = "default_cp_queue_drop_log_interval_secs")]
    pub queue_drop_log_interval_secs: u64,
}

fn default_cp_enabled() -> bool {
    true
}

fn default_cp_queue_capacity() -> usize {
    4096
}

fn default_cp_shadow_queue_capacity() -> usize {
    2048
}

fn default_cp_shadow_mode() -> bool {
    true
}

fn default_cp_allow_fault_injection() -> bool {
    false
}

fn default_cp_queue_drop_log_interval_secs() -> u64 {
    60
}

#[derive(Deserialize, Debug, Clone)]
pub struct MetrologyConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_metrics_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_queue_capacity() -> usize {
    8192
}

fn default_metrics_flush_interval_secs() -> u64 {
    30
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}

/// Private keys must not be readable or writable by group/other.
pub fn verify_file_permissions(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    if mode & 0o077 != 0 {
        return Err(format!(
            "Insecure permissions ({:o}) on private key: {}. Must be 0600 or 0400.",
            mode, path
        )
        .into());
    }

    Ok(())
}
