// Database access helpers.
//
// NOTE: Migrations are applied by the API binary via `sqlx::migrate!` with a
// path relative to `crates/api` (where the binary lives). Keeping lifecycle
// handling in the binary avoids fragile relative macro paths from library
// crates. This crate provides shared connection utilities only.

