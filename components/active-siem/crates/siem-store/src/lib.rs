//! `siem-store`: PostgreSQL persistence for `siem-core`'s `Event`/`Alert`
//! data model. See `store::Store` for the module-level rationale on why
//! Postgres and why the schema is shaped the way it is.

pub mod convert;
pub mod error;
mod schema;
mod store;

pub use error::{Result, StoreError};
pub use store::Store;
