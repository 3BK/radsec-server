# docs/TESTING.md

## Purpose

This document defines the testing strategy for **`kanidm_radsec_edge`** as a **Kanidm-aware, EAP-TLS-only RadSec edge service**.

The testing objective is to verify that the service remains:

- correct,
- fail-closed,
- reproducible,
- safe to operate in regulated and high-assurance environments,
- and suitable for **secure non-destructive testing (NDT)** and **bounded edge metrology**.

This guide covers:

- unit tests,
- integration tests,
- malformed corpus regression tests,
- shadow/NDT validation,
- release readiness checks,
- and PQ-ready test planning.

---

## Testing Principles

### 1. Fail closed
Tests must verify that malformed, unsupported, or unauthorized inputs are rejected safely.

### 2. Preserve trust boundaries
Tests should reinforce that:

- outer RadSec TLS trust remains strict,
- EAP-TLS-only enforcement remains strict,
- Kanidm remains the backend identity/EAP authority,
- NDT remains internal-only.

### 3. Prefer deterministic artifacts
Use deterministic fixtures, bounded synthetic inputs, and reproducible test vectors whenever possible.

### 4. Test both correctness and safety
For this service, “works” is not enough.
Tests must also evaluate:

- malformed input resilience,
- queue behavior,
- state-machine correctness,
- and logging/observability expectations.

### 5. Keep NDT non-destructive
Production-safe testing must not mutate the live forwarding path.
Use shadow validation, canary deployments, and staged replay tooling outside production.

---

## Test Layers

---

## 1. Unit Tests

Unit tests should validate isolated functional components with deterministic input/output behavior.

### Current expected areas
- config parsing
- private-key permission verification
- RADIUS packet parse / serialize
- `Message-Authenticator` verification
- EAP parse logic
- EAP-TLS-only enforcement
- peer certificate policy validation
- session state-machine transition rules
- control-plane shadow verdict behavior

### File
```text
tests/test.rs
```

### Example coverage expectations
- secure config loads correctly
- insecure key permissions fail
- tampered packets fail authenticator verification
- unsupported EAP methods are rejected
- shadow-path validation rejects malformed or unsupported traffic
- illegal state transitions are detected

---

## 2. Integration Tests

Integration tests should validate subsystem interaction boundaries.

### Current primary target
Transparent upstream proxy behavior to a mock UDP RADIUS backend representing the Kanidm RADIUS side.

### File
```text
tests/integration_proxy.rs
```

### Example coverage
- Access-Request forwarded to upstream
- Access-Challenge relayed correctly
- Access-Accept relayed correctly
- Access-Reject relayed correctly
- upstream timeout surfaced correctly
- response authenticator validation enforced

### Key goals
- ensure the edge preserves packet integrity
- ensure transparent proxy semantics remain correct
- ensure upstream failure behavior remains fail-closed

---

## 3. Malformed Corpus / Fuzz Regression Tests

Malformed corpus regression tests protect parser safety and protocol handling.

### File
```text
tests/fuzz_regressions.rs
```

### Objectives
- ensure malformed RADIUS packets do not panic the parser
- ensure malformed EAP payloads do not panic the parser
- ensure unsupported EAP methods are rejected
- ensure shadow-path validation also rejects malformed traffic
- keep at least one valid-reference anchor case in the corpus

### Corpus examples
Recommended malformed cases include:

- short packet
- header length mismatch
- invalid attribute length
- attribute overrun
- missing `EAP-Message`
- missing `Message-Authenticator`
- malformed EAP length
- missing EAP type byte
- unsupported EAP method
- tampered valid packet

### Expectation
No malformed corpus sample should cause:
- panic,
- infinite loop,
- queue blowout,
- or uncontrolled resource growth.

---

## 4. NDT / Shadow Validation Tests

The service includes an internal bounded control plane and shadow validation model.
Testing must verify that shadow/NDT remains:

- internal,
- bounded,
- non-destructive,
- and observability-safe.

### What to validate
- shadow parsing mirrors live packet safely
- shadow verdicts are emitted correctly
- queue pressure on shadow path does not destabilize data plane
- unsupported/malformed samples remain rejected in shadow mode
- no external control surface is required to run shadow tests

### Production rule
NDT must not become a hidden alternative data plane.

---

## 5. State Machine Tests

The explicit session state machine is a critical assurance feature.

### What to test
- legal transitions succeed
- illegal transitions fail deterministically
- state violations are counted/observable
- state tracker remains bounded and sane under malformed flow simulation
- shutdown/close behavior is consistent

### Example state flows to verify
- accepted TCP -> TLS handshake started -> TLS established
- TLS established -> peer identity validated
- peer identity validated -> RADIUS frame received -> RADIUS validated
- RADIUS validated -> EAP identity observed
- RADIUS validated -> EAP-TLS observed
- upstream pending -> challenge/accept/reject relayed
- any state -> closed/error

---

## 6. TLS and Peer Policy Tests

### Scope
These tests should validate policy logic on top of TLS material handling.

### Recommended checks
- fingerprint allow-list accepts expected peer
- fingerprint mismatch fails
- SAN URI prefix policy accepts expected peer
- SAN DNS suffix policy accepts expected peer
- missing SAN behavior obeys CN fallback setting
- invalid/missing peer identity fails closed

### Notes
Certificate parsing and policy handling should be tested separately from full live TLS handshake integration where possible for determinism.

---

## 7. Operational / Release Validation

In addition to Rust tests, every release candidate should pass operational validation.

### Required validation items
- startup with known-good config
- startup fails with insecure key permissions
- startup fails with invalid config
- startup fails with invalid TLS material
- listener binds correctly
- known-good peer can connect
- known-good EAP-TLS path reaches Kanidm backend
- logging is emitted in expected structure
- metrology flushes are visible
- queue drops stay within baseline under expected load

---

## Test Commands

### Run all tests
```bash
cargo test --tests -- --nocapture
```

### Run only unit/integration/fuzz regression sets
Examples:

```bash
cargo test --test test -- --nocapture
cargo test --test integration_proxy -- --nocapture
cargo test --test fuzz_regressions -- --nocapture
```

### Recommended CI gating
All test suites should pass before:

- image publication,
- runtime promotion,
- certificate/trust-policy change rollout,
- queue sizing changes,
- EAP policy changes,
- PQ-related dependency/profile change rollout.

---

## CI / Pipeline Expectations

The secure delivery pipeline should execute at minimum:

- formatting/lint checks
- unit tests
- integration proxy tests
- malformed corpus regression tests
- release build
- dependency scan
- SBOM generation
- container build validation
- artifact signing / provenance verification where applicable

### Recommended fail conditions
Fail pipeline if:
- any parser or state-machine test fails
- malformed corpus causes panic
- integration proxy response validation fails
- build artifact or dependency scan violates policy
- startup smoke validation fails in controlled environment

---

## Test Environment Guidance

### Local developer environment
Use for:
- fast unit test iteration
- malformed corpus development
- parser changes
- config model changes
- state-machine changes

### Staging / pre-production
Use for:
- full end-to-end RadSec path
- real certificate flows
- peer-policy validation
- canary traffic
- PQ/hybrid interoperability testing when applicable

### Production
Allowed:
- internal shadow validation
- canary release verification
- bounded metrology review

Not allowed:
- publicly exposed replay/fault injection endpoints
- uncontrolled packet mutation test planes
- unapproved trust-policy relaxation for test convenience

---

## Test Data and Fixture Guidance

### Sensitive data handling
Do not store:
- real private keys
- production certificates
- real secrets
- real user/device identities

### Preferred fixtures
Use:
- synthetic packet fixtures
- locally generated test certs
- mock RADIUS backend behavior
- deterministic byte strings
- sanitized metadata only

### Corpus hygiene
Maintain malformed corpus as a version-controlled artifact.
Changes to corpus should be reviewed like code.

---

## Performance and Load Testing

### Goals
Validate that bounded queues, rate limiter behavior, and upstream timeout posture remain safe under expected and burst conditions.

### What to observe
- handshake throughput
- queue pressure
- memory behavior
- reject categorization under malformed input
- upstream RTT under concurrency
- metrology flush overhead

### Rules
Load tests must not:
- disable bounded queue behavior
- remove rate limiting
- weaken peer policy
- bypass EAP-TLS-only checks

---

## PQ-Ready Testing Guidance

Because the service is documented as **PQ-ready**, testing should include a governance plan for PQ migration validation.

### Current expectations
PQ-ready testing should verify:
- no architectural assumption prevents hybrid PQ TLS rollouts later
- dependency/provider version reviews are tracked
- staged interoperability testing is planned before any production PQ profile changes
- operators do not confuse “PQ-ready” with “already universally PQ-enabled”

### Future PQ-specific test areas
When PQ or hybrid PQ profiles are introduced, test:
- handshake interoperability with approved peers
- fallback behavior with classical-only peers
- performance impact
- logging and metrology differences
- deployment rollback safety

---

## Release Readiness Checklist

Before promoting a release:

- [ ] all unit tests pass
- [ ] integration proxy tests pass
- [ ] malformed corpus regression tests pass
- [ ] no parser panic on malformed corpus
- [ ] state-machine tests pass
- [ ] startup validation passes
- [ ] known-good peer/path validation passes
- [ ] no unexpected queue drops in validation baseline
- [ ] dependency scan reviewed
- [ ] SBOM generated
- [ ] artifact provenance recorded
- [ ] rollback artifact available
- [ ] PQ-related dependency/profile changes explicitly reviewed if applicable

---

## Anti-Patterns

Do **not**:

- treat production as your primary fuzz target
- expose external test APIs for convenience
- use real production certificates or secrets as fixtures
- “temporarily” disable EAP-TLS-only policy to get tests green
- skip malformed corpus regression after parser changes
- assume PQ claims are validated without explicit test evidence

---

## Summary

Testing for `kanidm_radsec_edge` must prove more than feature correctness.

It must also prove:

- fail-closed behavior,
- parser safety,
- state-machine correctness,
- bounded queue discipline,
- safe NDT behavior,
- transparent upstream proxy correctness,
- and PQ-ready governance discipline.

The test program should therefore combine:

- deterministic unit tests,
- integration proxy tests,
- malformed corpus regression tests,
- staged operational validation,
- and controlled PQ-readiness test planning.
