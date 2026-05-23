# radius-server

A high-performance, hardened RADIUS-over-TLS (RadSec) server built in Rust. Designed for zero-trust environments, it atttempts to eliminate external dependencies for secret management while aligning with the aspirations of NIST SP 800-53, PCI DSS 4.0, NIST STIG, CIS, and ISO 27001.

## Security Architecture

* **Post-Quantum mTLS**: Enforces mutual TLS 1.3 with a FIPS-compliant cryptographic boundary (`aws-lc-rs`), mandating ECDHE with `P-384` paired with hybrid Post-Quantum key exchanges.
* **Local Secret Protection**: Eliminates cloud-api attack vectors by reading keys from local volumes while actively enforcing POSIX permission checks (`0600`/`0400`) at runtime.
* **Volumetric DoS Defense**: Utilizes an in-memory token-bucket governor keyed by IP address to drop abusive connections before expensive cryptographic handshakes occur.
* **Zero-Surface Containerization**: Statically compiled using `musl` with stripped symbols, producing a minimal, immutable runtime that executes as a non-root user inside a `scratch` container image.
* **Structured Audit Logging**: Outputs strict JSONL telemetry to `stdout` for tamper-resistant ingestion by SIEM tools.

## Project Structure

* `Cargo.toml`: Minimal-dependency definition with an optimized, stripped, and aborted-panic release profile.
* `.cargo/config.toml`: Target configuration forcing static C-runtime linkage.
* `config.toml`: Human-readable server configuration utilizing TOML.
* `src/main.rs`: Application initialization, structured logging setup, and orchestrator.
* `src/config.rs`: Validates TOML ingestion and enforces OS-level private key permissions.
* `src/crypto.rs`: Configures FIPS/PQ cryptography, ALPN validation, and mTLS.
* `src/server.rs`: High-throughput async connection loop with governor rate-limiting and graceful shutdown.
* `tests/security_tests.rs`: Automated test suite validating permission enforcement.

## Compilation & Testing

To execute the compliance test suite locally:
```bash
cargo test
```

To build the fully static, stripped 64-bit Linux binary via Docker:
```bash
docker build -t secure-radsec:latest .
```

To execute the compliance test suite locally:
```bash
cargo test
