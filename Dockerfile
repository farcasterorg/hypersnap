FROM rust:1.95 AS base

WORKDIR /usr/src/app

ARG MALACHITE_GIT_REPO_URL=https://github.com/informalsystems/malachite.git
ENV MALACHITE_GIT_REPO_URL=$MALACHITE_GIT_REPO_URL
ARG MALACHITE_GIT_REF=13bca14cd209d985c3adf101a02924acde8723a5
ARG ETH_SIGNATURE_VERIFIER_GIT_REPO_URL=https://github.com/CassOnMars/eth-signature-verifier.git
ENV ETH_SIGNATURE_VERIFIER_GIT_REPO_URL=$ETH_SIGNATURE_VERIFIER_GIT_REPO_URL
ARG ETH_SIGNATURE_VERIFIER_GIT_REF=8deb4a091982c345949dc66bf8684489d9f11889
ENV RUST_BACKTRACE=1
RUN <<EOF
set -eu
apt-get update && apt-get install -y build-essential libclang-dev git libjemalloc-dev llvm-dev make protobuf-compiler libssl-dev openssh-client cmake
cd ..
git clone $ETH_SIGNATURE_VERIFIER_GIT_REPO_URL
cd eth-signature-verifier
git checkout $ETH_SIGNATURE_VERIFIER_GIT_REF
cd ..

git clone $MALACHITE_GIT_REPO_URL
cd malachite
git checkout $MALACHITE_GIT_REF
EOF
# cargo-chef splits the build: every dependency (malachite included) compiles
# in its own layer, keyed only by Cargo.toml/Cargo.lock, so a source change
# rebuilds snapchain alone and CI can keep that layer in its cache.
RUN cargo install cargo-chef --locked

FROM base AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM base AS builder
COPY --from=planner /usr/src/app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.lock Cargo.toml ./
COPY proto ./proto
COPY src ./src

ENV RUST_BACKTRACE=full
# The binaries go to /out and target/ is dropped in the same layer, so the
# layer that changes with every commit stays small instead of holding every
# compiled dependency again.
RUN <<EOF
set -eu
cargo build --release --bins
mkdir -p /out
cp target/release/hypersnap target/release/shuttle target/release/native_register target/release/follow_blocks target/release/setup_local_testnet \
  target/release/submit_message target/release/perftest target/release/repair_block_event \
  target/release/inspect_block_event /out/
## Pre-generate some configurations we can use
# TOOD: consider doing something different here
/out/setup_local_testnet
rm -rf target
EOF

#################################################################################

FROM ubuntu:26.04

# Easier debugging within container
ARG GRPCURL_VERSION=1.9.4
ARG TARGETOS
ARG TARGETARCH
# ca-certificates is installed explicitly (not just as a curl recommendation) because
# tonic's `tls-native-roots` reads the system trust store at runtime.
RUN <<EOF
  set -eu
  apt-get update && apt-get install -y --no-install-recommends ca-certificates curl
  curl -fL https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_${TARGETOS}_${TARGETARCH}.deb > grpcurl.deb
  dpkg -i grpcurl.deb
  rm grpcurl.deb
  apt-get remove -y curl
  apt-get autoremove -y
  apt-get clean
  rm -rf /var/lib/apt/lists/*
EOF

WORKDIR /app
COPY --from=builder /usr/src/app/proto/definitions /app/proto
COPY --from=builder /usr/src/app/nodes /app/nodes
COPY --from=builder /out/ /app/

ENV RUSTFLAGS="-Awarnings"
ENTRYPOINT ["./hypersnap"]
CMD ["--config-path", "config.toml"]
