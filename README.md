*** The following is EXPERIMENTAL *** 

# kanidm_radsec_edge

A hardened, production-oriented **RADIUS-over-TLS (RadSec) edge service** built in Rust for **EAP-TLS-only** environments and intended to front a **Kanidm-native RADIUS / EAP-TLS backend**.

This project is designed for **zero-trust**, **high-assurance**, and **regulated** environments where secure transport, strict protocol enforcement, bounded observability, deterministic operational behavior, and **post-quantum readiness** are required.

> **Important compliance note**
>
> This software is **not** a certification, attestation, or guarantee of compliance.
>
> It is designed to help support **NIST SP 800-53 Rev. 5**, **PCI DSS 4.0**, **NIST STIG**, **CIS**, and **ISO 27001** readiness by providing security-oriented technical controls, implementation patterns, and deployment hooks.
>
> Actual compliance depends on:
>
> - deployment architecture,
> - cryptographic policy,
> - certificate / PKI governance,
> - logging and retention,
> - access control,
> - vulnerability management,
> - change management,
> - operating system hardening,
> - container / orchestrator hardening,
> - and operational procedures.

---

## Overview

`kanidm_radsec_edge` is a **Kanidm-aware RadSec edge** that:

- terminates **outer RadSec TLS** sessions,
- enforces **mutual TLS** for RadSec peers,
- accepts and validates **RADIUS Access-Request** traffic,
- enforces **EAP-TLS-only** policy at the edge,
- transparently proxies valid requests to a **Kanidm RADIUS backend**,
- relays **Access-Challenge**, **Access-Accept**, and **Access-Reject** responses,
- and emits bounded internal **control-plane**, **NDT**, and **metrology** events.

This service is intentionally **not** a full identity provider and **not** a general-purpose NAC platform. It is a **secure transport, protocol enforcement, and observability layer** for a **Kanidm-backed RadSec deployment**.

---

## Post-Quantum Readiness Position

This project is documented as **PQ-ready**, which means:

- it is architected for **cryptographic agility**,
- it is intended to track **NIST-standardized** post-quantum algorithms,
- it is designed so that future or profile-specific builds can prefer **hybrid post-quantum TLS key exchange**,
- and it separates **transport enforcement** from **identity authority** so that PQ transitions can be staged safely.

### Current PQ-ready posture

The intended PQ-ready posture for this edge is:

- **hybrid TLS key establishment** when supported and approved by deployment policy,
- continued classical interoperability fallback where required,
- compatibility with **ML-KEM**-based key establishment migration,
- compatibility with future **ML-DSA** / PQ-signature policy decisions for certificates and audit artifacts where organizationally appropriate.

### Important implementation note

PQ-ready documentation does **not** mean every build automatically enables PQ features today.

Organizations should treat PQ readiness as:

1. a design objective,
2. a cryptographic-agility requirement,
3. a migration roadmap,
4. and an explicit deployment decision tied to interoperability, PKI, and validation requirements.

---

## Security Architecture

### 1. TLS 1.3 mutual authentication

The service enforces **TLS 1.3** and requires **client certificates** from incoming RadSec peers. This provides a strong outer transport boundary for RADIUS over TLS.

### 2. PQ-ready cryptographic agility

The edge is designed so that TLS policy can evolve toward **hybrid post-quantum key establishment** without redesigning the application architecture.

Examples of PQ-ready expectations include:

- policy-controlled enablement of hybrid key exchange,
- explicit interoperability testing,
- fallback controls for peers that are not yet PQ-capable,
- change-managed rollout by deployment class.

### 3. Strict peer certificate policy

In addition to standard chain validation, the edge can enforce stricter peer policy constraints such as:

- SHA-256 fingerprint pinning,
- SAN URI prefix matching,
- SAN DNS suffix matching,
- optional CN fallback control.

This helps reduce implicit trust in CA-only validation and supports tighter peer identity governance.

### 4. EAP-TLS-only enforcement

The edge is designed for **EAP-TLS-only** environments and fail-closes on:

- non-EAP requests,
- unsupported EAP methods,
- EAP NAK downgrades,
- malformed EAP structures,
- malformed or policy-violating packets.

This removes unnecessary legacy authentication paths such as PEAP, TTLS, PAP, CHAP, and MSCHAPv2 from the edge service.

### 5. Local secret and key protection

The server reads key material from local volumes and verifies that the private key file is restricted to secure POSIX permissions (for example `0400` or `0600`) at startup.

### 6. Volumetric abuse resistance

Incoming connections are subject to a bounded per-source-IP rate limiter to reduce exposure to abusive or excessive connection rates before the service expends unnecessary compute on protocol handling.

### 7. Safe internal control plane

The service includes an internal, bounded **control-plane message queue** and an explicit **session state machine**. These are used for:

- state transition visibility,
- safe non-destructive testing (NDT),
- protocol shadow validation,
- internal metrology,
- and operational diagnostics.

### 8. Safe non-destructive testing (NDT)

NDT is implemented using **shadow validation** only:

- mirrored packets are evaluated on an internal bounded queue,
- packet parse / authenticator / policy checks are repeated,
- verdicts are recorded internally,
- and the live forwarding path is not modified by shadow processing.

This allows regression-oriented testing and protocol verification without introducing an external administrative test interface.

### 9. Bounded metrology

The service emits low-cardinality, bounded internal metrology samples covering transport, protocol, queue behavior, reject classes, and upstream timing. Metrics are aggregated to structured logs rather than exposing a separate metrics service in this revision.

### 10. Minimal runtime posture

The intended production deployment uses:

- static musl build,
- stripped release binary,
- non-root execution,
- immutable runtime image,
- read-only mounted configuration and certificates,
- and a read-only root filesystem where possible.

---

## Kanidm Alignment

This project is intended to front a **Kanidm-native RADIUS / EAP-TLS backend**.

The architectural separation of duties is:

### `kanidm_radsec_edge`
- secure RadSec transport termination,
- peer trust enforcement,
- packet validation,
- EAP-TLS-only enforcement,
- safe NDT,
- edge metrology,
- transparent proxy behavior.

### Kanidm
- authoritative RADIUS backend,
- authoritative EAP-TLS handling,
- identity authority,
- directory and authorization source,
- credential and certificate-policy authority.

This division helps keep the edge service focused on **transport, enforcement, and observability** while allowing Kanidm to remain the **identity and EAP authority**.

---

## Compliance Readiness Positioning

This implementation is designed to help support technical control objectives commonly associated with:

- **NIST SP 800-53 Rev. 5**
- **PCI DSS 4.0**
- **NIST STIG**
- **CIS Benchmarks / CIS Controls**
- **ISO 27001**

### Examples of control-supporting capabilities

#### Audit and accountability support
- structured JSON log output,
- deterministic internal event generation,
- explicit reject reasons,
- protocol and transport telemetry,
- state-transition visibility.

#### System and communications protection support
- TLS 1.3 transport security,
- mutual certificate authentication,
- peer certificate policy checks,
- PQ-ready cryptographic agility roadmap,
- fail-closed protocol enforcement.

#### Boundary protection and denial-of-service resistance support
- bounded rate limiting,
- packet length and attribute validation,
- bounded internal queues,
- timeouts on handshake and I/O paths.

#### Secure configuration and hardening support
- local TOML configuration,
- restricted private-key permission checks,
- minimal runtime image posture,
- non-root execution,
- support for immutable deployment patterns.

#### Change, testing, and monitoring support
- non-destructive shadow validation,
- explicit state machine,
- metrology snapshots,
- regression-oriented malformed corpus testing.

> **Important**
>
> Compliance frameworks require organizational, administrative, and infrastructure controls beyond the application itself.
> This project is best understood as a **security-focused technical component** that can contribute to those control objectives when deployed appropriately.

---

## Project Scope

### In scope
- RadSec transport handling
- strict peer TLS policy
- RADIUS packet framing and validation
- EAP-TLS-only policy enforcement
- transparent proxying to Kanidm
- bounded internal control plane
- bounded internal NDT
- bounded internal metrology
- structured JSON logs
- hardened runtime posture
- PQ-ready cryptographic migration posture

### Explicitly out of scope
- full identity provider behavior
- certificate issuance / enrollment
- full NAC / policy engine
- packet re-signing for split-secret topologies
- external admin API
- external test control API
- external metrics endpoint in this revision
- direct claims of framework certification / compliance

---

## Repository Structure

```text
.
├── Cargo.toml
├── config.toml
├── src
│   ├── lib.rs
│   ├── main.rs
│   ├── config.rs
│   ├── crypto.rs
│   ├── eap.rs
│   ├── kanidm.rs
│   ├── radius.rs
│   ├── control.rs
│   ├── metrics.rs
│   ├── state.rs
│   └── server.rs
└── tests
    ├── test.rs
    ├── integration_proxy.rs
    └── fuzz_regressions.rs
```

### File responsibilities

- `src/main.rs`  
  Application bootstrap, logging initialization, config load, TLS build, startup orchestration.

- `src/config.rs`  
  Configuration model, TOML load, private-key permission checks.

- `src/crypto.rs`  
  TLS 1.3 / mTLS configuration and peer certificate policy support.

- `src/radius.rs`  
  RADIUS packet structure, parse/serialize logic, `Message-Authenticator` verification, reject builder.

- `src/eap.rs`  
  EAP parsing andBelow are **raw, non-rendered Markdown files** for:

- `README.md`
- `SECURITY.md`
- `docs/ARCHITECTURE.md`
- `docs/CONTROL-MAPPING.md`

I updated them because the prior README no longer matched the intended product identity and target posture:

- your uploaded project currently shows the package/binary/config/runtime shape of the existing code (`radsec_server`, `RADSEC_CONFIG`, `/etc/radsec/config.toml`, TLS 1.3 + mTLS, rate limiting, packet framing, and upstream proxy flow), so a rename to **`kanidm_radsec_edge`** requires documentation changes. 【1-164c7a】【2-fc3f30】【10-7db587】【2-57ae0b】
- your current uploaded TLS code shows **TLS 1.3**, `aws_lc_rs`, and `SECP384R1`, but not a demonstrated PQ KEM path in the present source, so I rewrote the docs to describe **PQ readiness / crypto agility / migration posture** rather than claiming that PQ is already fully enabled by default in the currently uploaded code. 【3-35b352】【1-164c7a】
- that wording is aligned with current standards and implementation reality: NIST finalized **FIPS 203 (ML-KEM)** and **FIPS 204 (ML-DSA)** in August 2024, and current rustls documentation states support for **post-quantum hybrid key exchange with X25519MLKEM768**, with the `prefer-post-quantum` feature controlling preference, while the `rustls-post-quantum` material notes that ML-KEM support moved into rustls itself in 0.23.22+. 【8-e48cfd】【9-59009e】【6-a2c3e8】【7-021a45】【11-457714】
- Kanidm’s documentation explicitly lists **RADIUS** and **EAP-TLS** support, and RFC 6614 remains the defining transport profile for **RADIUS over TLS (RadSec)**, which is the basis for the edge role described in these files. 【4-d1d0ab】【5-8be035】【12-04b161】

---

## `README.md`

````markdown
# kanidm_radsec_edge

A hardened, production-oriented **RADIUS-over-TLS (RadSec) edge service** built in Rust for **EAP-TLS-only** environments and intended to front a **Kanidm-native RADIUS / EAP-TLS backend**.

`kanidm_radsec_edge` is designed for **zero-trust**, **high-assurance**, and **regulated** environments where secure transport, strict protocol enforcement, bounded observability, deterministic operational behavior, and **post-quantum readiness** are required.

> **Important compliance note**
>
> This software is **not** a certification, attestation, or guarantee of compliance.
>
> It is designed to help support **NIST SP 800-53 Rev. 5**, **PCI DSS 4.0**, **NIST STIG**, **CIS**, and **ISO 27001** readiness by providing security-oriented technical controls, implementation patterns, and deployment hooks.
>
> Actual compliance depends on:
>
> - deployment architecture,
> - PKI and certificate governance,
> - logging and retention,
> - access control,
> - vulnerability management,
> - change management,
> - operating system hardening,
> - container/orchestrator hardening,
> - and operational procedures.

---

## Overview

`kanidm_radsec_edge` is a **Kanidm-aware RadSec edge** that:

- terminates **outer RadSec TLS** sessions,
- enforces **mutual TLS** for RadSec peers,
- accepts and validates **RADIUS Access-Request** traffic,
- enforces **EAP-TLS-only** policy at the edge,
- transparently proxies valid requests to a **Kanidm RADIUS backend**,
- relays **Access-Challenge**, **Access-Accept**, and **Access-Reject** responses,
- and emits bounded internal **control-plane**, **NDT**, and **metrology** events.

This service is intentionally **not** a full identity provider and **not** a general-purpose NAC platform. It is a **secure transport, protocol enforcement, and observability layer** for a **Kanidm-backed RadSec deployment**.

---

## Security Architecture

### 1. TLS 1.3 mutual authentication

The service enforces **TLS 1.3** and requires **client certificates** from incoming RadSec peers. This provides a strong outer transport boundary for RADIUS over TLS in line with RFC 6614 deployment patterns.

### 2. Strict peer certificate policy

In addition to standard chain validation, the edge can enforce stricter peer policy constraints such as:

- SHA-256 fingerprint pinning,
- SAN URI prefix matching,
- SAN DNS suffix matching,
- optional CN fallback control.

This helps reduce implicit trust in CA-only validation and supports tighter peer identity governance.

### 3. EAP-TLS-only enforcement

The edge is designed for **EAP-TLS-only** environments and fail-closes on:

- non-EAP requests,
- unsupported EAP methods,
- EAP NAK downgrades,
- malformed EAP structures,
- malformed or policy-violating packets.

This removes unnecessary legacy authentication paths such as PEAP, TTLS, PAP, CHAP, and MSCHAPv2 from the edge service.

### 4. Local secret and key protection

The server reads key material from local volumes and verifies that the private key file is restricted to secure POSIX permissions (for example `0400` or `0600`) at startup.

### 5. Volumetric abuse resistance

Incoming connections are subject to a bounded per-source-IP rate limiter to reduce exposure to abusive or excessive connection rates before the service expends unnecessary compute on protocol handling.

### 6. Safe internal control plane

The service includes an internal, bounded **control-plane message queue** and an explicit **session state machine**. These are used for:

- state transition visibility,
- safe non-destructive testing (NDT),
- protocol shadow validation,
- internal metrology,
- and operational diagnostics.

### 7. Safe non-destructive testing (NDT)

NDT is implemented using **shadow validation** only:

- mirrored packets are evaluated on an internal bounded queue,
- packet parse / authenticator / policy checks are repeated,
- verdicts are recorded internally,
- and the live forwarding path is not modified by shadow processing.

This allows regression-oriented testing and protocol verification without introducing an external administrative test interface.

### 8. Bounded metrology

The service emits low-cardinality, bounded internal metrology samples covering transport, protocol, queue behavior, reject classes, and upstream timing. Metrics are aggregated to structured logs rather than exposing a separate metrics service in this revision.

### 9. PQ-ready cryptographic posture

`kanidm_radsec_edge` is intended to be **post-quantum ready**, meaning:

- crypto-agile TLS provider selection,
- migration planning for **hybrid post-quantum key exchange**,
- architecture that can evolve toward NIST-standardized algorithms such as **ML-KEM** and **ML-DSA**,
- and documentation/deployment patterns that avoid locking the design into classical-only cryptography.

**PQ-ready** in this project means **prepared for migration and hybrid deployment**, not a blanket statement that every build automatically enables every PQ mechanism by default.

### 10. Minimal runtime posture

The intended production deployment uses:

- static musl build,
- stripped release binary,
- non-root execution,
- immutable runtime image,
- read-only mounted configuration and certificates,
- and a read-only root filesystem where possible.

---

## Kanidm Alignment

This project is intended to front a **Kanidm-native RADIUS / EAP-TLS backend**.

The architectural separation of duties is:

### `kanidm_radsec_edge`
- secure RadSec transport termination,
- peer trust enforcement,
- packet validation,
- EAP-TLS-only enforcement,
- PQ-ready transport posture,
- safe NDT,
- edge metrology,
- transparent proxy behavior.

### Kanidm
- authoritative RADIUS backend,
- authoritative EAP-TLS handling,
- identity authority,
- directory and authorization source,
- credential and certificate-policy authority.

This division helps keep the edge service focused on **transport, enforcement, and observability** while allowing Kanidm to remain the **identity and EAP authority**.

---

## Compliance Readiness Positioning

This implementation is designed to help support technical control objectives commonly associated with:

- **NIST SP 800-53 Rev. 5**
- **PCI DSS 4.0**
- **NIST STIG**
- **CIS Benchmarks / CIS Controls**
- **ISO 27001**

### Examples of control-supporting capabilities

#### Audit and accountability support
- structured JSON log output,
- deterministic internal event generation,
- explicit reject reasons,
- protocol and transport telemetry,
- state-transition visibility.

#### System and communications protection support
- TLS 1.3 transport security,
- mutual certificate authentication,
- peer certificate policy checks,
- fail-closed protocol enforcement,
- PQ-ready crypto-agility posture.

#### Boundary protection and denial-of-service resistance support
- bounded rate limiting,
- packet length and attribute validation,
- bounded internal queues,
- timeouts on handshake and I/O paths.

#### Secure configuration and hardening support
- local TOML configuration,
- restricted private-key permission checks,
- minimal runtime image posture,
- non-root execution,
- support for immutable deployment patterns.

#### Change, testing, and monitoring support
- non-destructive shadow validation,
- explicit state machine,
- metrology snapshots,
- regression-oriented malformed corpus testing.

> **Important**
>
> Compliance frameworks require organizational, administrative, and infrastructure controls beyond the application itself.
> This project is best understood as a **security-focused technical component** that can contribute to those control objectives when deployed appropriately.

---

## Project Scope

### In scope
- RadSec transport handling
- strict peer TLS policy
- RADIUS packet framing and validation
- EAP-TLS-only policy enforcement
- transparent proxying to Kanidm
- bounded internal control plane
- bounded internal NDT
- bounded internal metrology
- structured JSON logs
- hardened runtime posture
- PQ-ready migration posture

### Explicitly out of scope
- full identity provider behavior
- certificate issuance / enrollment
- full NAC / policy engine
- packet re-signing for split-secret topologies
- external admin API
- external test control API
- external metrics endpoint in this revision
- direct claims of framework certification/compliance

---

## Repository Structure

```text
.
├── Cargo.toml
├── config.toml
├── src
│   ├── lib.rs
│   ├── main.rs
│   ├── config.rs
│   ├── crypto.rs
│   ├── eap.rs
│   ├── kanidm.rs
│   ├── radius.rs
│   ├── control.rs
│   ├── metrics.rs
│   ├── state.rs
│   └── server.rs
└── tests
    ├── test.rs
    ├── integration_proxy.rs
    └── fuzz_regressions.rs
```

### File responsibilities

- `src/main.rs`
  Application bootstrap, logging initialization, config load, TLS build, startup orchestration.

- `src/config.rs`
  Configuration model, TOML load, private-key permission checks.

- `src/crypto.rs`
  TLS 1.3 / mTLS configuration and peer certificate policy support.

- `src/radius.rs`
  RADIUS packet structure, parse/serialize logic, `Message-Authenticator` verification, reject builder.

- `src/eap.rs`
  EAP parsing and EAP-TLS-only enforcement helpers.

- `src/kanidm.rs`
  Transparent upstream UDP RADIUS exchange to Kanidm.

- `src/control.rs`
  Internal control-plane event and shadow-validation types.

- `src/state.rs`
  Explicit session state machine and transition validation.

- `src/metrics.rs`
  Bounded metrology samples and periodic aggregation.

- `src/server.rs`
  Listener, rate limiting, TLS accept, packet loop, validation, upstream proxy path.

---

## Quick Start

### Prerequisites

- Rust `1.90.0+`
- `musl-tools`
- `clang`
- `llvm`
- `cmake`
- `cargo`

Optional for containerized static builds:
- Docker / Podman with BuildKit support

### Build

```bash
cargo build --release
```

### Run tests

```bash
cargo test --tests -- --nocapture
```

### Run locally

```bash
export RADSEC_CONFIG=/etc/radsec/config.toml
cargo run --release
```

---

## Configuration

The service reads:

```text
/etc/radsec/config.toml
```

by default, or the path set in:

```text
RADSEC_CONFIG
```

### Example `config.toml`

```toml
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
require_san_dns_suffix = null
allow_subject_cn_fallback = false

[radius]
shared_secret = "radsec"
require_message_authenticator = true
max_packet_size = 4096

[upstream]
address = "10.0.0.15:1812"
timeout_secs = 5

[eap]
enforce_eap_tls_only = true

[control_plane]
enabled = true
queue_capacity = 4096
shadow_queue_capacity = 2048
shadow_mode = true
allow_fault_injection = false
queue_drop_log_interval_secs = 60

[metrology]
enabled = true
queue_capacity = 8192
flush_interval_secs = 30
```

---

## Configuration Guidance

### `[server]`
Controls listener behavior, rate limiting, and timeout posture.

### `[tls]`
Provides the server certificate, private key, and trusted client-CA bundle for incoming RadSec peers.

### `[peer_policy]`
Adds stricter peer identity constraints beyond certificate chain validation.

### `[radius]`
Controls shared-secret expectations and `Message-Authenticator` enforcement.

### `[upstream]`
Defines the Kanidm RADIUS backend socket and response timeout.

### `[eap]`
Enables strict **EAP-TLS-only** behavior.

### `[control_plane]`
Enables the secure internal control plane and shadow validation behavior.

### `[metrology]`
Enables bounded edge metrology and periodic aggregation to structured logs.

---

## Transparent Proxy Requirement

This service validates and relays RADIUS packets transparently. As a result:

> **The upstream Kanidm RADIUS backend must use the same shared secret as the edge**
> unless the implementation is extended to rewrite request/response authenticators.

Default shared secret:

```text
radsec
```

---

## Key and File Permissions

Recommended runtime file ownership and permissions:

```text
/etc/radsec/config.toml      0444 or 0400
/etc/radsec/server.pem       0444
/etc/radsec/client_ca.pem    0444
/etc/radsec/server.key       0400 or 0600
```

The service enforces secure private-key permissions at startup and fails closed if they are too permissive.

---

## Logging

The service emits structured **JSON** logs to stdout.

Typical event classes include:

- server startup and shutdown,
- TLS handshake success/failure,
- peer identity observations,
- packet framing and validation,
- reject reasons,
- internal control-plane events,
- metrology flush snapshots.

These logs are intended for ingestion by centralized logging/SIEM systems.

---

## Control Plane, NDT, and Metrology

### Internal control plane

The internal control plane carries bounded events such as:

- session opened,
- peer identity observed,
- state transition,
- RADIUS packet observed,
- EAP packet observed,
- reject reason,
- shadow verdict,
- session closed.

### Explicit state machine

The service uses an explicit session state machine with states such as:

- `AcceptedTcp`
- `TlsHandshakeStarted`
- `TlsEstablished`
- `PeerIdentityValidated`
- `RadiusFrameReceived`
- `RadiusValidated`
- `EapIdentityObserved`
- `EapTlsObserved`
- `UpstreamPending`
- `UpstreamChallengeRelayed`
- `UpstreamAcceptRelayed`
- `UpstreamRejectRelayed`
- `Closed`
- `Error`

Illegal state transitions are treated as security-relevant anomalies and counted in metrology.

### NDT (non-destructive testing)

NDT uses:

- bounded internal shadow queues,
- mirrored packet validation,
- no external replay endpoint,
- no external fault-injection endpoint,
- no mutation of the live forwarding path.

### Metrology

Current metrology categories include:

- sessions opened / closed,
- packet counts and byte counts,
- TLS handshake count and average latency,
- upstream request count and average RTT,
- reject categories,
- queue-drop counters,
- state-violation counters.

---

## PQ Readiness Notes

The project should be understood as **PQ-ready / crypto-agile**, which means:

- the design anticipates migration to NIST-standardized **ML-KEM** for key establishment,
- the design anticipates migration to **ML-DSA** (or equivalent approved signature strategies) for long-lived signature use cases where applicable,
- deployment guidance should prefer **hybrid classical + PQ** approaches during transition,
- and the service should avoid hardcoding itself into a classical-only future.

Practical PQ migration for this service should be treated as a staged program:

1. maintain strong classical TLS defaults now,
2. preserve provider and key-exchange agility,
3. test hybrid PQ key exchange in pre-production,
4. track provider and interop maturity,
5. adopt production-safe hybrid PQ paths when operationally justified.

---

## Tests

### `tests/test.rs`
Covers:
- config parsing,
- private-key permission validation,
- RADIUS parse/serialize logic,
- `Message-Authenticator` verification,
- EAP-TLS-only enforcement,
- peer certificate policy checks,
- session state tracking,
- shadow-validation behavior.

### `tests/integration_proxy.rs`
Covers:
- end-to-end upstream proxy behavior,
- Access-Challenge relay,
- Access-Accept relay,
- Access-Reject relay,
- upstream timeout handling.

### `tests/fuzz_regressions.rs`
Covers:
- malformed RADIUS packet corpus,
- malformed EAP corpus,
- parser non-panic guarantees,
- shadow-path malformed-corpus regression behavior,
- valid baseline anchor case.

---

## Production Container Guidance

Use a minimal static runtime with:

- non-root execution,
- read-only root filesystem,
- no added capabilities,
- no-new-privileges,
- read-only certificate/config mounts.

### Example runtime posture

```bash
docker run -d \
  --name kanidm-radsec-edge \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 2083:2083/tcp \
  -v /opt/radsec/config:/etc/radsec:ro \
  kanidm-radsec-edge:prod
```

---

## Operational Recommendations

For high-assurance deployment, pair this service with:

- strong internal PKI governance,
- certificate lifecycle management,
- centralized log retention and review,
- OS and container hardening baselines,
- image signing / provenance controls,
- SBOM generation and dependency scanning,
- vulnerability management,
- infrastructure-level monitoring,
- change-management and deployment review processes,
- and a documented PQ migration roadmap.

---

## Limitations

Current revision limitations:

- no CRL / OCSP revocation enforcement,
- no external metrics endpoint,
- no dynamic upstream pool or active failover set,
- no packet re-signing for split-secret proxy topologies,
- no certificate issuance or enrollment workflow,
- no externally accessible NDT control interface,
- no claim of framework certification or formal compliance,
- PQ readiness described as **migration posture**, not universal default enablement.

---

## Recommended Next Improvements

Potential future enhancements:

- CRL / OCSP enforcement,
- upstream health checks and pool support,
- optional packet re-signing for split-secret topologies,
- signed regression corpus handling,
- Prometheus/OpenTelemetry export,
- richer audit event IDs,
- hardened deployment examples for Kubernetes / OpenShift,
- compliance-annotated control mapping documentation,
- explicit hybrid PQ TLS deployment profiles.

---

## Summary

`kanidm_radsec_edge` is a **secure, bounded, EAP-TLS-only, PQ-ready Kanidm-aware RadSec edge** intended for **high-assurance** and **regulated** environments.

It is designed to help support:

- secure transport,
- strict protocol boundaries,
- safe non-destructive testing,
- bounded edge metrology,
- PQ migration readiness,
- and readiness-oriented control objectives for common regulatory and hardening frameworks.

For identity authority and EAP-TLS backend behavior, pair it with **Kanidm**.  
For transport security, enforcement, observability, and PQ-ready edge posture at the RadSec boundary, use **`kanidm_radsec_edge`**.
