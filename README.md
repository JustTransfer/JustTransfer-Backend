# JustTransfer Backend

Rust backend for JustTransfer, an encrypted file transfer service with two delivery modes:

- **Connected transfer** (account-to-account)
- **Anonymous transfer** (link/password-style flow)

This repository contains the API server, database models/migrations, session/auth logic, and S3-compatible object storage integration.

## Current status

This project is under active development (`v0.1.0`). API contracts and behavior may change.

## Core features

- Account registration and login flow (OPAQUE-based auth flow in server logic)
- Session-based authentication and fresh-login checks for sensitive operations
- Encrypted file metadata/message handling for connected and anonymous transfers
- S3-compatible object storage support (tested with MinIO-style endpoints)
- PostgreSQL persistence with Diesel migrations
- Email flows for verification and password reset
- Background monthly quota reset task (`master` / `development` modes)

## Tech stack

- **Language/runtime:** Rust 2021, Tokio
- **Web:** Axum, Tower, tower-http
- **Database:** PostgreSQL + Diesel
- **Storage:** AWS SDK S3 client (S3-compatible endpoint)
- **Crypto/auth:** libsodium, OPAQUE, argon2, sha2
- **Mail:** lettre

## Prerequisites

- Rust toolchain (stable)
- PostgreSQL (or a running container)
- S3-compatible object storage (for local dev: MinIO)
- `libsodium` development libraries

Linux packages (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y libpq-dev libsodium-dev
```

Windows:

- Download the PostgreSQL `libpq` development files
- Set the `PATH` environment variable to include the PostgreSQL `bin` directory, e.g.: `C:\Program Files\PostgreSQL\17\bin`

## Quick start (local development)

1) Copy environment file:

```bash
cp .env.sample .env
```

2) Start local PostgreSQL + MinIO (example):

```bash
docker network create justtransfer || true
docker run -d --name jt-postgres --network justtransfer -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=just_transfer -p 5432:5432 postgres:17
docker run -d --name jt-minio --network justtransfer -e MINIO_ROOT_USER=admin -e MINIO_ROOT_PASSWORD=password -p 9000:9000 -p 9001:9001 minio/minio server /data --console-address ":9001"
```

3) Update `.env` for host-run backend (typical local values):

```dotenv
DATABASE_URL=postgres://postgres:postgres@localhost/just_transfer
MINIO_URL=http://localhost:9000
FRONTEND_URL=https://localhost
```

4) Run the backend:

```bash
cargo run
```

The server binds to `0.0.0.0:80` (see `src/consts.rs`). On Linux, binding to port `80` may require elevated privileges or `CAP_NET_BIND_SERVICE`.

## Environment variables

Required variables are loaded at startup from the process environment:

- `FRONTEND_URL`
- `POSTGRESQL_USERNAME`
- `DATABASE_URL`
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`
- `MINIO_URL`
- `S3_BUCKET_NAME`
- `S3_BUCKET_NAME_ANONYMOUS`
- `SERVER_MODE` (`master`, `slave`, or `development`)
- `SMTP_HOST`
- `SMTP_MAIL`
- `SMTP_PASSWORD`

Use `.env.sample` as the baseline configuration.

## Database and Diesel

Migrations are embedded and executed automatically on server startup.

If you want Diesel CLI for schema/migration work:

```bash
cargo install diesel_cli --no-default-features --features postgres
diesel setup
diesel migration run
diesel print-schema > src/schema.rs
```

## API overview

Current route groups from `src/main.rs`:

- Public: `/api/config`, register/login start/end, verify email, reset password
- Authenticated: user info, logout, key lookups, message upload/download/delete
- Fresh login required: delete account, add key, update registration
- Anonymous transfer: create/upload/login flow and metadata/download endpoints

The backend currently exposes JSON and multipart endpoints; formal OpenAPI documentation is not yet included.

## Server modes

- `master`: runs monthly quota reset task on month boundaries (UTC)
- `development`: runs quota reset task every minute (for testing)
- `slave`: does not run the quota reset scheduler

## Project layout

```text
src/
  api_handlers/      # HTTP handlers (anonymous/auth/connected/misc)
  server/            # initialization, cron, mail, and service logic
  models.rs          # Diesel models
  schema.rs          # Diesel-generated schema
  consts.rs          # limits, env key registry, app constants
  main.rs            # router and middleware setup
migrations/          # SQL migrations
```

## Testing

Run tests with:

```bash
cargo test
```

> Note: current test module includes placeholder/failing exploration tests and should be expanded before production releases.

## Contributing

Contributions are welcome.

- Open an issue to discuss bug fixes or feature ideas
- Fork the repository and submit a pull request with your changes
- Ensure code is well-documented and includes tests where appropriate
