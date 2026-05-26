# Build Stage
FROM rust:1.76 AS builder

RUN apt-get update && apt-get install -y musl-tools cmake clang llvm
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/radsec
COPY . .

ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime Stage (Distroless / Scratch for zero attack surface)
FROM scratch

COPY --from=builder /usr/src/radsec/target/x86_64-unknown-linux-musl/release/kanidm_radsec_edge /bin/kanidm_radsec_edge

# Ensure non-root execution (PCI DSS / STIG constraint)
USER 1000:1000

# Require environment variable to point to config if not using default
ENV RADSEC_CONFIG="/etc/radsec/config.toml"

ENTRYPOINT ["/bin/kanidm_radsec_edge"]
