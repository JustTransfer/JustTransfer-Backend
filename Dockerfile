FROM rust:1.90 as builder
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

FROM debian:forky-slim

RUN apt-get update && apt-get install -y libpq5 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/JustTransfer /usr/local/bin/JustTransfer

EXPOSE 80

CMD ["JustTransfer"]