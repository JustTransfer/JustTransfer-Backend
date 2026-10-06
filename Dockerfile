FROM rust:1.97 AS builder
WORKDIR /usr/src/myapp

# Build deps: libpq headers for diesel/postgres
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev pkg-config && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo install --locked --path .

FROM debian:forky-slim

# libpq5 for postgres, ca-certificates for outbound TLS (Stripe, SMTP, S3)
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/justtransfer-backend /usr/local/bin/justtransfer-backend

EXPOSE 80

CMD ["justtransfer-backend"]