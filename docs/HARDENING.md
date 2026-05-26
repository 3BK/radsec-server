# docs/HARDENING.md

## Purpose

This document defines the **hardening guidance** for **`kanidm_radsec_edge`** as a **Kanidm-aware, EAP-TLS-only RadSec edge service**.

This guide is intended to support secure deployment in:

- high-assurance environments,
- regulated environments,
- zero-trust architectures,
- and environments that require a **PQ-ready** / crypto-agile migration posture.

It covers:

- application hardening,
- runtime hardening,
- filesystem and secret handling,
- network boundary hardening,
- queue/state hardening,
- logging and monitoring hardening,
- and crypto / PQ-readiness hardening guidance.

---

## Hardening Objectives

The hardening goals for `kanidm_radsec_edge` are:

1. minimize exposed attack surface
2. fail closed under malformed, unsupported, or unsafe input
3. isolate transport enforcement from identity authority
4. keep secrets and trust anchors tightly controlled
5. preserve safe NDT and bounded metrology without adding attackable control surfaces
6. support crypto agility and PQ-readiness without making premature or unsafe claims

---

## 1. Application Hardening

### EAP-TLS-only mode
The service should run with **EAP-TLS-only** enforcement enabled.

This reduces exposed protocol surface by rejecting:
- PEAP
- TTLS
- PAP
- CHAP
- MSCHAPv2
- EAP NAK downgrade behavior
- malformed EAP structures

### Fail-closed input handling
The service should fail closed for:
- malformed packet lengths
- invalid RADIUS attribute structure
- unsupported RADIUS codes
- missing or invalid `Message-Authenticator`
- peer-policy mismatch
- invalid upstream response authenticator
- unsupported or malformed EAP

### Peer-policy hardening
Do not rely on CA chain validation alone if stronger peer identity requirements are available.
Prefer deployment with one or more of:
- fingerprint allow-list
- SAN URI prefix policy
- SAN DNS suffix policy
- CN fallback disabled unless explicitly justified

### Configuration discipline
Use explicit configuration values for:
- bind address
- timeouts
- queue capacities
- peer policy
- upstream destination
- shared secret
- EAP policy

Avoid runtime mutation of security-critical parameters outside the approved deployment process.

---

## 2. Runtime Hardening

### Run as non-root
Always run the service as a **non-root** user.

### Read-only filesystem
Prefer:
- read-only root filesystem
- read-only config/cert volume
- immutable image or host package install
- no writable application directories unless explicitly required

### No unnecessary privileges
For containers:
- drop all capabilities
- enable `no-new-privileges`
- avoid privileged or host-network modes unless explicitly required and approved
- enforce seccomp and apparmor/default confinement where available

### Minimal runtime image
Prefer:
- static build
- stripped release binary
- minimal runtime base
- no shell
- no package manager
- no compilers/tools in runtime image

---

## 3. Filesystem and Secret Hardening

### Expected file layout

```text
/etc/radsec/config.toml
/etc/radsec/server.pem
/etc/radsec/server.key
/etc/radsec/client_ca.pem
```

### File permission guidance

Recommended permissions:

```text
/etc/radsec/config.toml      0444 or 0400
/etc/radsec/server.pem       0444
/etc/radsec/client_ca.pem    0444
/etc/radsec/server.key       0400 or 0600
```

The service already performs an explicit check that private-key permissions are not readable or writable by group/other. Do not weaken this.

### Secret handling guidance
- do not bake production secrets into build context when avoidable
- mount secrets read-only at runtime
- control who can update cert/key/config volumes
- treat shared secret and trust anchors as controlled configuration artifacts

---

## 4. Network Boundary Hardening

### Inbound hardening
Only allow inbound:
- `TCP 2083` from approved RadSec peers
- known/approved source ranges or peer identities

### Outbound hardening
Only allow outbound:
- configured Kanidm RADIUS backend
- required logging/monitoring destinations
- other approved operational dependencies only

### Segmentation
Place the edge in a dedicated identity/AAA boundary segment where possible.

### Avoid broad exposure
Do not place the service directly on broadly exposed internet edge without explicit architecture and DDoS planning.

---

## 5. TLS and Cryptographic Hardening

### Current transport posture
The service is intended to use:
- TLS 1.3
- mutual certificate authentication
- modern provider-backed cryptography
- strong elliptic-curve parameters
- strict peer validation

### Certificate policy hardening
Prefer:
- restricted trust anchors
- peer fingerprint pinning or SAN constraints
- certificate lifecycle review
- documented CA ownership and renewal paths

### ALPN
Only require ALPN `"radius"` if all peers are known to support it correctly in your environment.

### Revocation
This revision does not yet implement CRL/OCSP enforcement. Compensating controls should include:
- short certificate lifetimes
- strong issuance governance
- rapid certificate replacement process
- peer inventory review
- trust-anchor change control

---

## 6. RADIUS / EAP Hardening

### Require `Message-Authenticator`
Keep `require_message_authenticator = true` unless a very carefully justified compatibility exception has been approved.

### Restrict method surface
Keep:
```toml
[eap]
enforce_eap_tls_only = true
```

### Transparent proxy constraint
The upstream shared secret must match unless packet re-signing is introduced as an explicitly reviewed feature.

### Malformed input resilience
Maintain regression tests for:
- malformed packet lengths
- invalid attribute lengths
- unsupported EAP types
- tampered request packets
- malformed EAP structures

---

## 7. Queue and State Hardening

### Bounded queues only
Use bounded queues for:
- control plane
- shadow/NDT
- metrology

Do **not** convert queues to unbounded in production as a convenience measure.

### Monitor queue pressure
Monitor:
- `queue_drop_control`
- `queue_drop_shadow`
- `queue_drop_metrics`

Queue drops are signals of pressure and should trigger review, but bounded queues are part of the safe design.

### State-machine hardening
Treat state violations as security/quality signals. Investigate increases in:
- illegal transitions
- unexpected session lifecycle behavior
- shadow/live divergence symptoms

---

## 8. NDT Hardening

### Allowed NDT model
Use only:
- internal shadow validation
- bounded internal queues
- passive packet mirroring for verification
- canary and staged test paths outside production when deeper testing is needed

### Not allowed in production
- external replay endpoints
- unauthenticated fault injection
- public admin/testing APIs
- hidden bypasses around peer or EAP policy

### Why
The NDT design must remain **non-destructive** and must not become an alternate privileged attack surface.

---

## 9. Logging and Metrology Hardening

### Logging
Use structured JSON logs and forward them to a central collector.

Recommended protections:
- integrity-preserving log pipeline
- synchronized time
- controlled retention
- restricted access to log sinks
- role-based access to dashboards/review surfaces

### Metrology
The internal metrology plane should remain:
- low-cardinality
- bounded
- internal-only in this revision

Do not expose an external metrics endpoint unless it is explicitly designed, reviewed, authenticated/authorized, and hardened.

### Sensitive data handling
Avoid including:
- secrets
- raw private key material
- unnecessary PII
- unnecessary full packet bodies

---

## 10. Build and Supply Chain Hardening

### Build guidance
Use:
- pinned toolchain/version strategy
- signed or verified source inputs where possible
- reproducible release build process
- release profile hardening
- minimal binary output

### Recommended controls
- SBOM generation
- dependency scanning
- provenance recording
- signed container images or approved artifact digests
- change review for cryptography-related dependency changes

### PQ-related dependency governance
Track:
- TLS provider updates
- cryptographic feature changes
- hybrid/PQ support maturity
- interoperability caveats
- standardization status and errata

---

## 11. PQ-Ready Hardening Guidance

### What PQ-ready means here
In this project, PQ-ready means:

- crypto-agile architecture,
- migration-compatible design,
- ability to stage hybrid classical+PQ transport profiles later,
- governance that prevents premature, unsafe, or undocumented PQ changes.

### What operators should do
- document PQ migration roadmap
- review provider capability and standards maturity
- test hybrid PQ transport in staging before any production enablement
- preserve rollback paths for cryptographic profile changes
- do not overstate current production validation

### What operators should not do
- do not mark production “PQ secure” by assumption
- do not enable new PQ/hybrid profiles without interoperability testing
- do not skip compliance/change review because a feature is “future safe”

---

## 12. Host and Platform Hardening

### Bare-metal / VM
Apply:
- CIS/STIG-aligned host baseline
- local firewall
- least-privilege service account
- unnecessary service removal
- patching process
- tamper-resistant logging
- time synchronization
- encrypted storage if required by policy

### Container platforms
Apply:
- non-root execution
- read-only root filesystem
- dropped capabilities
- no privilege escalation
- network policy
- image digest pinning
- admission policy for secure pod/container posture
- approved secret store integration

---

## 13. Hardening Checklist

### Application
- [ ] EAP-TLS-only enabled
- [ ] `Message-Authenticator` enforcement enabled
- [ ] strict peer policy configured
- [ ] fail-closed behavior preserved
- [ ] bounded queues enabled
- [ ] state-machine monitoring enabled

### Runtime
- [ ] non-root user
- [ ] read-only root filesystem
- [ ] `/etc/radsec` mounted read-only
- [ ] no-new-privileges enabled
- [ ] capabilities dropped
- [ ] minimal runtime image/base

### PKI / Secrets
- [ ] server key is `0400` or `0600`
- [ ] config/trust paths controlled
- [ ] CA bundle reviewed
- [ ] peer inventory current
- [ ] trust changes under change control

### Logging / Monitoring
- [ ] central log forwarder enabled
- [ ] retention configured
- [ ] monitoring alerts defined
- [ ] queue and state anomalies reviewed regularly

### PQ readiness
- [ ] PQ migration roadmap documented
- [ ] dependency/provider posture tracked
- [ ] hybrid PQ TLS testing planned or documented where relevant
- [ ] no unapproved PQ-related cryptographic changes in production

---

## 14. Hardening Anti-Patterns

Do **not**:

- run as root
- mount config/certs read-write without strong justification
- disable EAP-TLS-only policy for convenience
- disable peer policy broadly as a quick fix
- expose external NDT APIs in production
- ignore queue-drop or state-violation signals
- claim PQ readiness as universally complete without evidence
- skip supply-chain review for cryptographic dependency changes

---

## Summary

Hardening for `kanidm_radsec_edge` should focus on:

- strict transport and protocol boundaries
- least-privilege runtime
- immutable and tightly controlled config/cert handling
- bounded and observable internal control/metrology planes
- disciplined PKI and shared-secret governance
- and a realistic, governed PQ-ready migration posture.

This service should be operated as a **minimal, strict, transparent RadSec enforcement edge** in front of **Kanidm’s authoritative RADIUS/EAP-TLS backend**.
