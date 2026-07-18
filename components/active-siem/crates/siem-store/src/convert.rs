use crate::error::{StoreError, Result};
use siem_core::{EventId, Severity};

pub fn severity_to_i16(s: Severity) -> i16 {
    s as i16
}

pub fn severity_from_i16(v: i16) -> Result<Severity> {
    match v {
        0 => Ok(Severity::Info),
        1 => Ok(Severity::Low),
        2 => Ok(Severity::Medium),
        3 => Ok(Severity::High),
        4 => Ok(Severity::Critical),
        other => Err(StoreError::InvalidSeverity(other)),
    }
}

/// `siem_core::EventId` is `u64`; every BIGINT column here is a signed
/// 64-bit integer, so ids above `i64::MAX` (which nothing in this codebase
/// currently produces -- ids come from small in-process counters) can't be
/// represented. Checked rather than silently truncated/wrapped, since a
/// silently-corrupted event id in a security audit trail is exactly the
/// kind of bug that should fail loudly at the boundary, not surface later
/// as a mysteriously missing or wrong record.
pub fn event_id_to_i64(id: EventId) -> Result<i64> {
    i64::try_from(id).map_err(|_| StoreError::EventIdOutOfRange(id))
}

pub fn event_id_from_i64(id: i64) -> EventId {
    // Every id we ever write went through event_id_to_i64 first, so this
    // is always in range; u64::try_from would only fail for negative
    // values, which never occur since we always insert non-negative i64s.
    id as EventId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_round_trips() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(severity_from_i16(severity_to_i16(s)).unwrap(), s);
        }
    }

    #[test]
    fn invalid_severity_is_rejected() {
        assert!(severity_from_i16(5).is_err());
        assert!(severity_from_i16(-1).is_err());
    }

    #[test]
    fn event_id_round_trips() {
        for id in [0u64, 1, 42, u32::MAX as u64, i64::MAX as u64] {
            assert_eq!(event_id_from_i64(event_id_to_i64(id).unwrap()), id);
        }
    }

    #[test]
    fn event_id_above_i64_max_is_rejected() {
        assert!(event_id_to_i64(u64::MAX).is_err());
        assert!(event_id_to_i64(i64::MAX as u64 + 1).is_err());
    }
}
