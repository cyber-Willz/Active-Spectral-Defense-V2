//! Fuzzes `extract_7z` against fully attacker-controlled bytes, with the
//! same `GuardLimits` a real deployment would use. Same invariant as the
//! zip/gzip/tar targets: never panic, never read or allocate unboundedly
//! regardless of what the archive header claims.
#![no_main]
use archive_guard::{extract_7z, GuardBudget, GuardLimits};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut budget = GuardBudget::new(GuardLimits::default());
    let _ = extract_7z(Cursor::new(data), &mut budget);
});
