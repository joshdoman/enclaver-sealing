# Stage 1: Build the application
FROM rust:1.86-slim as builder

WORKDIR /usr/src/app

# Only copy Cargo files to cache dependencies
COPY Cargo.toml Cargo.lock ./
# Create a dummy src directory to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release

# Copy the actual source code and build the application
COPY src ./src
RUN touch src/main.rs && \
    cargo build --release

# Stage 2: Create the final, minimal image
FROM debian:12-slim

# Build argument for local development
ARG LOCAL

WORKDIR /opt/app/

# Install networking tools for local development
RUN if [ "$LOCAL" = "true" ]; then \
        apt-get update && apt-get install -y \
            ca-certificates \
            curl \
            dnsutils \
        && rm -rf /var/lib/apt/lists/* \
        && update-ca-certificates; \
    fi

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/sealed-enclave /usr/local/bin/sealed-enclave

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/sealed-enclave"]