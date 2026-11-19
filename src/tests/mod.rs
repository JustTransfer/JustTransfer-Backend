//! Cross-module tests. Unit tests live next to the code they cover.
//!
//! - `http`: the router end to end (middleware, sessions, status codes).
//! - `connected`, `link`, `payment`: the `server::*` layer against a real
//!   PostgreSQL database and, where needed, S3. See `support` for setup.

pub(crate) mod support;

mod connected;
mod http;
mod link;
mod payment;
