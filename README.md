# JustTransfer Backend

A Rust (Axum) API server for JustTransfer - an encrypted file-transfer service supporting two delivery modes:
- Account/Connected transfers (account-to-account)
- Link/Anonymous transfers (link/password-style flow)

This repository contains the Axum web server, Diesel-based PostgreSQL integration (embedded migrations), S3-compatible storage (AWS SDK), OPAQUE-based auth flows, session handling, and email helpers.

Tech stack
- Rust 2021, Tokio
- Axum web framework
- Diesel + PostgreSQL
- AWS SDK for S3 (S3-compatible endpoints supported)
- OPAQUE (opaque-ke), libsodium, argon2
- lettre for SMTP

Quickstart (development)
1. Install prerequisites:
   - Rust toolchain (stable), cargo
   - PostgreSQL accessible from the machine
   - S3-compatible service (e.g. MinIO) if you want storage locally
   - System libs: libpq (libpq-dev) and libsodium-dev on Debian/Ubuntu

2. Copy and edit the environment file:
   cp .env.sample .env
   Edit `.env` and set DATABASE_URL and other values. DATABASE_URL must be a full Postgres connection string.

3. Start dependent services (Postgres, S3) using Docker or your environment.

4. Run the backend:
   cargo run

By default, the server listens on BACKEND_URL (see `.env.sample`, default: 0.0.0.0:80).

Environment variables
The server requires several environment variables. The primary ones (see `src/consts.rs` and `.env.sample`):
- `BACKEND_URL` - server listener address (e.g. 0.0.0.0:80)
- `FRONTEND_URL` - allowed CORS origin (used to set allowed origin header)
- `DATABASE_URL` - full Postgres connection string (required)
- `POSTGRESQL_USERNAME` - kept for compatibility (not used for connection when DATABASE_URL present)
- `RUSTFS_USER` - S3 access key
- `RUSTFS_PASSWORD` - S3 secret key
- `RUSTFS_URL` - S3 endpoint URL (e.g. http://localhost:9000)
- `S3_BUCKET_NAME` - bucket the service will ensure exists
- `SERVER_MODE` - one of: master, slave, development
- `SMTP_HOST`, `SMTP_MAIL`, `SMTP_PASSWORD` - SMTP configuration
- `DUMMY_EMAIL` - email used for dummy data

Session and authentication
- Sessions use tower-sessions MemoryStore (in-memory) and the cookie name is `user_session` by default.
- Session lifetimes are controlled by: SESSION_DURATION_MINUTES and FRESH_SESSION_DURATION_MINUTES.
- Authentication uses the OPAQUE protocol (server uses opaque-ke). Client implementations must perform matching OPAQUE client flows.

Server modes
- master: scheduler runs monthly reset task on the 1st UTC.
- development: scheduler runs every minute (useful for testing; also prints emails to logs).
- slave: scheduler is disabled.

API overview (high level)
See `src/main.rs` and handlers under `src/api_handlers/` for full behavior. Main route groups include:
- Public endpoints
  - GET  `/api/config`
  - POST `/api/register/start`
  - POST `/api/register/end`
  - POST `/api/login/start`
  - POST `/api/reset-password/request`
  - POST `/api/reset-password/end/{token}`
  - POST `/api/verify-email/{id}`

- Authenticated endpoints (require session)
  - GET  `/api/user`
  - POST `/api/logout`
  - GET  `/api/pubkey/{id}`
  - GET  `/api/user/{email}/pubkey`
  - GET/POST/DELETE `/api/user/saved-transfer`
  - POST `/api/login/end` (completes login and creates session)

- Fresh-login required (sensitive operations)
  - DELETE `/api/user/{email}`
  - PUT    `/api/user/addkey`
  - POST   `/api/register/update`

- Link (anonymous/connected) transfers
  - POST `/api/link/message/start`
  - POST `/api/link/message` (upload metadata + create multipart upload)
  - POST `/api/link/message/{id}/uploadfinish/{file_id}`
  - POST `/api/link/message/{id}/login/start`
  - POST `/api/link/message/{id}/login/end`
  - GET  `/api/link/message/{id}/metadata`
  - GET  `/api/link/message/{id}` (returns a presigned download URL)
  - PUT/DELETE `/api/link/message/{id}`

For exact request/response shapes consult `src/api_handlers/*` - handlers perform validation and base64/OPAQUE decoding.

Storage
- The server uses the AWS SDK for S3 and will create the bucket named by S3_BUCKET_NAME if it does not exist.
- The `.env.sample` contains examples; the code does not rely on a separate anonymous bucket (only S3_BUCKET_NAME is ensured).

Email
- Emails are sent using lettre. In `development` SERVER_MODE the email contents are printed to logs (the SMTP connection is still configured).

Database migrations
- Diesel migrations are embedded and executed at startup via `diesel_migrations::embed_migrations!()`.

Build, test, Docker
- Run locally: `cargo run`
- Build release: `cargo build --release`
- Tests: `cargo test`

Docker: the Dockerfile builds and installs the `JustTransfer` binary and exposes port 80. Example:
  docker build -t justtransfer-backend .
  docker run --env-file .env -p 80:80 justtransfer-backend

Notes & production considerations
- Environment variables are required at startup; missing/invalid values cause initialization to fail.
- Sessions are in-memory (MemoryStore). For production, replace with a persistent session store.
- OPAQUE requires client-side support for the protocol used here - ensure clients implement compatible OPAQUE flows.
- The service creates a dummy user and a dummy anonymous transfer on startup (see `src/server/init.rs`).

Contributing
Contributions welcome. Open an issue to discuss features or bugs, and submit PRs with tests where appropriate.

License
See LICENSE file for license details.
