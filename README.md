# JustTransfer Backend

JustTransfer Backend is the Rust/Axum API service for the JustTransfer encrypted file-transfer product. The server supports the following flow:

- Anonymous link transfers for one-time, password-protected.
- Higher limits for registered users.
- Transfers and password saving for registered users.

The implementation uses Diesel with PostgreSQL, AWS S3-compatible storage, OPAQUE-based authentication, in-memory session cookies, and SMTP for email notifications.

## Current architecture

The application entry point is in [src/main.rs](src/main.rs). It initializes the app state, configures CORS, mounts route groups, and starts the HTTP server.

Key parts of the codebase:

- [src/main.rs](src/main.rs): router setup, middleware, CORS, startup, listener binding.
- [src/server/init.rs](src/server/init.rs): validates env vars, creates the PostgreSQL pool, runs Diesel migrations, initializes OPAQUE settings, initializes S3, starts background tasks, and creates the dummy user/transfer.
- [src/server/connected.rs](src/server/connected.rs): account registration, login, key management, saved transfers, counters, and transfer logic.
- [src/server/link.rs](src/server/link.rs): anonymous transfer upload/metadata/download and expiry handling.
- [src/server/cron.rs](src/server/cron.rs): scheduling for monthly transfer resets and daily cleanup.
- [src/server/mail.rs](src/server/mail.rs): SMTP mail sending and development-mode console logging.
- [src/api_handlers](src/api_handlers): HTTP handlers for public, authenticated, and link-based endpoints.
- [src/models.rs](src/models.rs), [src/schema.rs](src/schema.rs): Diesel models and generated schema.
- [src/consts.rs](src/consts.rs): runtime configuration and transfer limits loaded from environment variables.

## Prerequisites

Before running the backend, install:

- Rust stable toolchain and Cargo.
- PostgreSQL instance reachable from the app.
- S3-compatible object storage such as MinIO or another AWS S3-compatible service.
- System libraries:
  - libpq / libpq-dev
  - libsodium-dev

The code expects a configured Rust toolchain before running `cargo` commands. If your machine does not have a default toolchain, run:

```bash
rustup default stable
```

## Configuration

The app reads environment variables at startup and fails fast if required values are missing or invalid. The canonical list is in [src/consts.rs](src/consts.rs) and the sample env file is [.env.sample](.env.sample).

Create a local environment file:

```bash
cp .env.sample .env
```

The server uses the following environment variables:

### Required runtime variables

- `BACKEND_URL`: address the server binds to, for example `0.0.0.0:80`.
- `FRONTEND_URL`: origin used for CORS; the server injects this as an allowed origin.
- `DATABASE_URL`: full PostgreSQL connection string. This is the real database connection value used by the app.
- `RUSTFS_USER`: S3 access key.
- `RUSTFS_PASSWORD`: S3 secret key.
- `RUSTFS_URL`: S3 endpoint URL such as `http://localhost:9000`.
- `S3_BUCKET_NAME`: bucket the app ensures exists on startup.
- `SERVER_MODE`: one of `master`, `slave`, or `development`.
- `SMTP_HOST`: SMTP hostname.
- `SMTP_MAIL`: sender email address.
- `SMTP_PASSWORD`: SMTP password.
- `DUMMY_EMAIL`: email used for the automatically created dummy account.

### Session and auth variables

- `SESSION_DURATION_MINUTES`: in-memory session inactivity expiry.
- `FRESH_SESSION_DURATION_MINUTES`: max age of a fresh login before re-authentication is required.
- `RESET_PASSWORD_TOKEN_DURATION_MINUTES`: lifetime of a password reset token.

### Transfer limits and pricing

These are loaded as integer values from environment variables and drive the allowed transfer limits:

- `MAX_NUMBER_ANONYMOUS_TRANSFERS_TOT`
- `MAX_LIFETIME_ANONYMOUS`
- `MAX_FILE_SIZE_ANONYMOUS`
- `CHUNK_SIZE_ANONYMOUS`
- `MAX_DOWNLOADS_ANONYMOUS`
- `MAX_NUMBER_ACCOUNTS`
- `PRICE_CONNECTED`
- `MAX_NUMBER_CONNECTED_TRANSFERS_MONTH`
- `CHUNK_SIZE_CONNECTED`
- `MAX_LIFETIME_CONNECTED`
- `MAX_FILE_SIZE_CONNECTED`
- `MAX_DOWNLOADS_CONNECTED`
- `PRICE_PREMIUM`
- `MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH`
- `MAX_LIFETIME_CONNECTED_PREMIUM`
- `MAX_FILE_SIZE_CONNECTED_PREMIUM`
- `MAX_DOWNLOADS_CONNECTED_PREMIUM`

### Compatibility fields in .env.sample

The sample file also contains `POSTGRESQL_USERNAME`, `POSTGRESQL_PASSWORD`, `POSTGRESQL_DB_NAME`, and `S3_BUCKET_NAME_ANONYMOUS`. These are not used by the current server startup code. The actual database connection uses `DATABASE_URL`, and the current S3 bootstrap only ensures the bucket in `S3_BUCKET_NAME` exists.

## Server modes

`SERVER_MODE` affects background jobs:

- `master`: monthly reset task and daily cleanup run on their normal schedules.
- `development`: both background tasks run every 60 seconds and mail is logged instead of sent.
- `slave`: scheduler is disabled.

This behavior is implemented in [src/server/cron.rs](src/server/cron.rs) and [src/server/mail.rs](src/server/mail.rs).

## Running locally

After filling in the required environment variables, start the server:

```bash
cargo run
```

The server listens on the value in `BACKEND_URL` and boots with:

- PostgreSQL migration execution
- OPAQUE settings generation if needed
- S3 bucket creation if it does not exist
- dummy user and dummy anonymous transfer creation
- background scheduler startup

## Docker

The project includes a Dockerfile that builds the binary and runs it on port 80.

```bash
docker build -t justtransfer-backend .
docker run --env-file .env -p 80:80 justtransfer-backend
```

The container exposes port `80` and starts the binary directly.

## API surface

The route set is configured in [src/main.rs](src/main.rs) and is the authoritative reference for the backend API.

### Public endpoints

- `GET /api/config`
- `POST /api/register/start`
- `POST /api/register/end`
- `POST /api/login/start`
- `POST /api/verify-email/{id}`
- `POST /api/reset-password/request`
- `POST /api/reset-password/end/{token}`

### Authenticated account routes

These require a valid user session:

- `GET /api/user`
- `POST /api/logout`
- `GET /api/pubkey/{id}`
- `GET /api/user/{email}/pubkey`
- `GET /api/user/saved-transfer`
- `POST /api/user/saved-transfer`
- `DELETE /api/user/saved-transfer/{id}`
- `POST /api/login/end`

### Fresh-login-required routes

These require both authentication and a fresh session timestamp:

- `DELETE /api/user/{email}`
- `PUT /api/user/addkey`
- `POST /api/register/update`

### Link transfer routes

Anonymous or linked transfers use these routes:

- `POST /api/link/message/start`
- `POST /api/link/message`
- `POST /api/link/message/{id}/uploadfinish/{file_id}`
- `GET /api/link/message/{id}/metadata`
- `GET /api/link/message/{id}`
- `POST /api/link/message/{id}/login/start`
- `POST /api/link/message/{id}/login/end`
- `PUT /api/link/message/{id}`
- `DELETE /api/link/message/{id}`
- `POST /api/link/message/{id}/password/start`
- `POST /api/link/message/{id}/password/end`

The route handlers validate base64 and OPAQUE payloads and return HTTP status codes defined in [src/error.rs](src/error.rs).

## Auth and session model

- Session storage is `tower_sessions::MemoryStore`.
- The cookie name is `user_session`.
- Session expiry is configured with `SESSION_DURATION_MINUTES`.
- Sensitive account actions require a fresh session based on `FRESH_SESSION_DURATION_MINUTES`.
- Authentication is based on the OPAQUE protocol and the server stores OPAQUE settings in PostgreSQL.

## Storage and data flow

- The app initializes an AWS S3 client using `RUSTFS_USER`, `RUSTFS_PASSWORD`, and `RUSTFS_URL`.
- It ensures the bucket named by `S3_BUCKET_NAME` exists at startup.
- Link transfers and file metadata are stored in PostgreSQL; file payloads are stored in S3.
- Background cleanup removes expired anonymous transfers and resets user monthly counters as configured.

## Email behavior

The mailer is initialized in [src/server/mail.rs](src/server/mail.rs):

- In `development` mode, emails are logged to stdout instead of sent.
- The SMTP connection is still created, but the message is not delivered.
- In `master` and `slave` modes, the app attempts to use SMTP normally.

## Development, tests, and build

The project has a basic Cargo setup and includes a placeholder test file at [src/tests.rs](src/tests.rs). It does not currently contain a mature automated test suite.

Useful commands:

```bash
cargo fmt
cargo build
cargo test

# Diesel CLI commands
cargo install diesel_cli --no-default-features --features postgres
diesel setup
diesel migration run
diesel print-schema > src/schema.rs
```

The repository currently contains a deliberately failing placeholder test in [src/tests.rs](src/tests.rs), so `cargo test` is not a passing suite at the moment. Replace or expand those tests before relying on the suite for verification.

## License

See [LICENSE](./LICENSE).
