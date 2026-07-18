use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] postgres::Error),

    #[error("(de)serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("severity value {0} out of range (expected 0..=4)")]
    InvalidSeverity(i16),

    #[error("event id {0} does not fit in a signed 64-bit column (siem-core::EventId is u64; \
             values above i64::MAX are not representable in this schema's BIGINT columns)")]
    EventIdOutOfRange(u64),
}

pub type Result<T> = std::result::Result<T, StoreError>;
