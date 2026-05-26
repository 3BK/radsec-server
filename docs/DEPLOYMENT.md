# docs/DEPLOYMENT.md

## Purpose

This document describes how to deploy **`kanidm_radsec_edge`** safely in production as a **Kanidm-aware, EAP-TLS-only RadSec edge service**.

This guide assumes:

- **RadSec transport** on TCP `2083`
- **EAP-TLS only**
- **Kanidm-native RADIUS / EAP-TLS backend**
- **mutual TLS** for RadSec peers
- **non-root**, **minimal**, **immutable** runtime posture where possible
- **PQ-ready** deployment intent with crypto-agile policy management

This document focuses on deployment architecture, runtime layout, security posture, configuration placement, secrets handling, and operational integration.

---

## Deployment Model

### Recommended topology

```text
[NAD / AP / Controller / RadSec peer]
              |
          TCP 2083 / TLS
              |
      [kanidm_radsec_edge]
         container or VM
              |
         UDP 1812 / RADIUS
              |
      [Kanidm RADIUS backend]
```

### Recommended role separation

`kanidm_radsec_edge` should own:

- outer RadSec transport termination,
- peer certificate policy,
- EAP-TLS-only enforcement,
- bounded control-plane/NDT,
- bounded metrology,
- transparent RADIUS proxy behavior.

Kanidm should own:

- RADIUS backend behavior,
- EAP-TLS processing,
- identity authority,
- authorization source,
- certificate-to-identity policy.

---

## Deployment Targets

This service can be deployed on:

- hardened Linux hosts,
- minimal VM images,
- rootless or non-root containers,
- orchestrated container platforms,
- isolated network segments used for AAA / identity-edge services.

### Strongly preferred targets

- hardened container image on a minimal runtime,
- dedicated VM or host in an identity / network security segment,
- deployment with explicit firewall policy allowing only required flows.

---

## Runtime Requirements

### Network
- inbound: `TCP 2083` from trusted RadSec peers
- outbound: `UDP 1812` (or configured upstream RADIUS port) to Kanidm backend
- outbound: centralized logging path if using a collector / forwarder
- optional: configuration / PKI distribution path outside runtime

### Filesystem
The service expects:

```text
/etc/radsec/config.toml
/etc/radsec/server.pem
/etc/radsec/server.key
/etc/radsec/client_ca.pem
```

The config path may be overridden using:

```text
RADSEC_CONFIG
```

### User / permissions
Run as a **non-root** user.

Recommended permissions:

```text
/etc/radsec/config.toml      0444 or 0400
/etc/radsec/server.pem       0444
/etc/radsec/client_ca.pem    0444
/etc/radsec/server.key       0400 or 0600
```

Do not make the private key group-readable or world-readable.

---

## Container Deployment

### Recommended runtime posture

Use a minimal, non-root image and enforce:

- read-only root filesystem
- dropped Linux capabilities
- `no-new-privileges`
- read-only `/etc/radsec`
- seccomp and apparmor/default confinement if available
- no shell / package manager in runtime image
- explicit stop signal handling
- immutable infrastructure pattern where practical

### Example `docker run`

```bash
docker run -d \
  --name kanidm-radsec-edge \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 2083:2083/tcp \
  -v /opt/radsec/config:/etc/radsec:ro \
  --restart unless-stopped \
  kanidm-radsec-edge:prod
```

### Recommended additional runtime settings

If supported by your platform:

- CPU and memory limits
- log driver configuration
- explicit health supervision via external checks
- host firewall policy
- pinned image digest
- signed image verification
- platform admission policies for non-root and read-only rootfs

---

## Bare-Metal / VM Deployment

### Recommended service model
Use:

- a dedicated service account,
- a locked-down working directory,
- read-only mounted config + certificate paths,
- strict file ownership and modes,
- a service manager such as `systemd`,
- centralized journal or log forwarding.

### Recommended host controls
- hardened OS baseline
- local firewall enabled
- unused services removed/disabled
- time synchronization enabled
- disk encryption when appropriate
- restricted administrative access
- patching and EDR/monitoring as required by policy

---

## Kubernetes / Orchestrated Deployment Guidance

### Security posture
For orchestrated environments, apply:

- `runAsNonRoot: true`
- read-only root filesystem
- no privilege escalation
- all capabilities dropped
- memory and CPU requests/limits
- dedicated namespace and network policy
- `ConfigMap` for non-sensitive config if appropriate
- secret volume or CSI-backed secret store for keys/certs
- pod disruption budget if required
- image digest pinning
- admission control for hardened pods

### Networking
Restrict:

- ingress to `TCP 2083` from approved peers only
- egress to Kanidm backend only
- egress to logging / monitoring only as required

### Volumes
Mount `/etc/radsec` read-only.

Do not mount writable secrets or configuration unless absolutely necessary.

---

## Configuration Management

### Primary config path
Default:

```text
/etc/radsec/config.toml
```

Override with:

```text
RADSEC_CONFIG
```

### Change management expectations
Treat the config file as controlled infrastructure configuration.
Recommended controls:

- version-controlled source of truth
- approval workflow
- environment-specific overlays
- deployment hashing / provenance
- rollback plan
- post-change validation checklist

### Example production config

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

## Secrets and PKI

### Private key handling
The private key must be provisioned securely and stored locally with restrictive permissions.

### Certificate chain
The service expects:

- server certificate for the edge
- trusted client CA for incoming RadSec peers

### PKI governance recommendations
Maintain documented processes for:

- issuance
- renewal
- revocation approach
- peer enrollment and trust anchoring
- certificate naming policy
- PQ migration planning for certificate strategy where applicable

### PQ-ready PKI guidance
For PQ-ready posture:

- maintain crypto-agile CA and issuance procedures
- document candidate hybrid / PQ certificate migration paths
- avoid hard-coded assumptions that prevent future hybrid or PQ-capable certificate strategy

---

## Shared Secret Alignment

This application uses a transparent proxy pattern for RADIUS packets.

> **The upstream Kanidm RADIUS backend must use the same shared secret as the edge**
> unless packet re-signing is explicitly implemented.

Default shared secret:

```text
radsec
```

If you need split-secret topologies, treat that as a separate feature and design review item.

---

## Logging and Monitoring

### Logging
The service emits JSON logs to stdout/stderr depending on runtime configuration.

Recommended handling:

- forward to centralized logging
- enforce retention
- protect integrity of logs
- correlate by host, container, session, and timestamp
- retain deployment metadata with security events

### Monitoring
Recommended platform monitoring includes:

- process health
- restart counts
- CPU/memory usage
- socket/listener availability
- upstream timeout rates
- reject trends
- queue drop counters
- state violation counts

### Metrology
The internal metrology plane aggregates and periodically emits low-cardinality summaries.
Use log pipeline parsing or sidecar/agent extraction if centralized dashboards are needed.

---

## Network Security Guidance

### Ingress policy
Allow only:

- approved RadSec peers
- approved source subnets / peer classes
- approved transport port (`2083/tcp`)

### Egress policy
Allow only:

- Kanidm upstream RADIUS address/port
- required logging and monitoring sinks
- necessary local infrastructure services

### Segmentation
Deploy the edge in a dedicated identity or AAA boundary zone where possible.

---

## Capacity and Scaling

### Scale guidance
This service is intended to be horizontally scalable when deployed behind policy-appropriate load balancing, provided:

- peer certificate policy remains consistent
- upstream Kanidm capacity is sufficient
- shared secret posture is consistent
- certificate and config distribution is controlled

### Capacity considerations
Review:

- handshake rates
- session concurrency
- queue sizing
- upstream RTT and timeout profile
- container/host memory sizing
- logging throughput

---

## Health and Readiness

This revision does not define an external health endpoint.

Recommended health model:

### Process-level checks
- service process running
- listener bound to `TCP 2083`
- config and cert files present and readable
- upstream dependency reachable by controlled external health tooling

### Synthetic checks
Use controlled probe clients in non-production windows or in a dedicated canary tier.
Do not expose external NDT control endpoints in production.

---

## Deployment Validation Checklist

Before go-live, verify:

- [ ] binary/image digest matches approved artifact
- [ ] running as non-root
- [ ] `/etc/radsec` mounted read-only
- [ ] private-key file mode is `0400` or `0600`
- [ ] listener bound to correct address/port
- [ ] trusted client CA is correct
- [ ] peer certificate policy configured as intended
- [ ] EAP-TLS-only enabled
- [ ] shared secret matches Kanidm backend
- [ ] upstream Kanidm address reachable
- [ ] logging pipeline working
- [ ] queue sizes reviewed
- [ ] restart behavior tested
- [ ] rollback path documented
- [ ] capacity test completed
- [ ] malformed packet regression tests passed
- [ ] PQ migration posture documented for this environment

---

## Post-Deployment Validation

After deployment, verify:

- [ ] successful service startup
- [ ] TLS handshake success from approved peer
- [ ] expected EAP-TLS challenge flow through Kanidm
- [ ] expected Access-Accept behavior
- [ ] expected Access-Reject behavior for unsupported methods
- [ ] no unexpected queue drops
- [ ] no illegal state transitions
- [ ] central logs received and indexed
- [ ] monitoring alerts wired

---

## Rollback Guidance

A rollback plan should include:

- last known good image/binary
- last known good config
- last known good certificates
- recovery procedure for failed startup due to permissions/config errors
- network policy reversal if new ingress/egress rules were introduced
- change record references

Rollback should be tested in staging before production use.

---

## Deployment Anti-Patterns

Do **not**:

- run as root
- mount `/etc/radsec` read-write unless absolutely necessary
- expose a management shell in runtime image
- enable broad outbound access
- skip private-key permission validation
- treat PQ readiness as “automatically solved”
- expose external NDT or fault-injection interfaces in production
- send logs to unsecured sinks
- deploy without central time sync

---

## PQ-Ready Deployment Guidance

To support PQ readiness operationally:

- maintain a documented PQ migration roadmap
- keep TLS provider and dependency versions under active review
- test staged hybrid PQ TLS in pre-production where applicable
- document interoperability boundaries for peers that are not PQ-capable
- track standards and provider maturity
- keep certificate and transport policy agile

PQ readiness should be treated as a long-horizon controlled migration, not a one-time toggle.

---

## Summary

A safe production deployment of `kanidm_radsec_edge` should provide:

- hardened runtime posture,
- strict RadSec and EAP-TLS policy enforcement,
- tightly controlled filesystem and secrets handling,
- strong segmentation and logging,
- bounded internal NDT and metrology,
- transparent upstream proxy alignment with Kanidm,
- and explicit PQ-ready migration planning.
