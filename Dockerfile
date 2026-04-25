FROM rust:1.80-slim as builder

# Install build dependencies if needed (e.g., pkg-config, libssl-dev for some crates)
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/aup

# Copy workspace configuration and lockfile
COPY Cargo.toml Cargo.lock ./

# Copy all crates
COPY crates ./crates

# Build the issuer and the demo app in release mode
RUN cargo build --release -p license-issuer -p demo-app

# ---------------------------------------------------
# Minimal Runtime Image
# ---------------------------------------------------
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (like ca-certificates if needed)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the built binaries from the builder stage
COPY --from=builder /usr/src/aup/target/release/license-issuer /usr/local/bin/
COPY --from=builder /usr/src/aup/target/release/demo-app /usr/local/bin/

# Copy the licenses folder for the demo
COPY licenses ./licenses

# Set the default entrypoint to the demo app
CMD ["demo-app", "licenses/license.signed.json", "licenses/keys/public.key", "licenses/runtime_input.normal.json"]
