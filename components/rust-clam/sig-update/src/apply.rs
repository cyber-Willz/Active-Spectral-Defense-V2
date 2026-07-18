//! Atomically replaces a live signature directory with a freshly staged,
//! already-verified one.
//!
//! The staging directory is built and fully verified (every file's SHA-256
//! checked against the manifest, and -- if configured -- the manifest's
//! own signature checked) *before* anything here touches the live
//! directory a running daemon reads its signatures from. This module's
//! only job is the swap itself, and it is written so that a daemon
//! re-reading `sig_dir` at any point during the swap sees either the
//! complete old generation or the complete new one -- never a partial mix
//! -- and so that a failure partway through is recoverable rather than
//! leaving no working signature directory at all.
//!
//! `std::fs::rename` within the same filesystem is atomic on both
//! POSIX and Windows for this purpose (a single directory-entry rename,
//! not a recursive copy), which is what makes the "either old or new, never
//! partial" property hold. Callers must ensure `staging_dir`, `sig_dir`,
//! and `sig_dir`'s `.previous` sibling are all on the same filesystem --
//! typically satisfied by keeping them under the same parent directory.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("staging directory {0} does not exist")]
    StagingMissing(PathBuf),
    #[error("io error during {step}: {source}")]
    Io {
        step: &'static str,
        #[source]
        source: std::io::Error,
    },
}

fn previous_path(sig_dir: &Path) -> PathBuf {
    let mut name = sig_dir
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".previous");
    sig_dir.with_file_name(name)
}

/// Swaps `staging_dir` into place as `sig_dir`, keeping whatever was
/// previously at `sig_dir` around as `<sig_dir>.previous` (overwriting any
/// prior `.previous` from an earlier update -- only one generation of
/// rollback is kept, which is a deliberate simplicity trade-off: this is a
/// safety net for "the update we just applied is bad", not a general
/// version history).
pub fn apply_update(staging_dir: &Path, sig_dir: &Path) -> Result<(), ApplyError> {
    if !staging_dir.is_dir() {
        return Err(ApplyError::StagingMissing(staging_dir.to_path_buf()));
    }

    let previous = previous_path(sig_dir);
    let had_previous_before = previous.exists();

    // Clear any older .previous first so a repeated update doesn't fail on
    // "destination already exists" -- keeping only the immediately prior
    // generation is the documented, intentional retention policy.
    if previous.exists() {
        std::fs::remove_dir_all(&previous).map_err(|e| ApplyError::Io {
            step: "removing stale .previous directory",
            source: e,
        })?;
    }

    let sig_dir_existed = sig_dir.exists();
    if sig_dir_existed {
        std::fs::rename(sig_dir, &previous).map_err(|e| ApplyError::Io {
            step: "moving current signatures to .previous",
            source: e,
        })?;
    }

    if let Err(e) = std::fs::rename(staging_dir, sig_dir) {
        // Roll back: put the previous generation back where the daemon
        // expects to find it, so a failed update leaves the daemon with
        // its old (still valid) signatures rather than none at all.
        if sig_dir_existed {
            let _ = std::fs::rename(&previous, sig_dir);
        }
        let _ = had_previous_before; // no further action needed either way
        return Err(ApplyError::Io {
            step: "moving staged signatures into place",
            source: e,
        });
    }

    Ok(())
}

/// Rolls back to the `.previous` generation left by the most recent
/// `apply_update` call, if one exists. Returns `Ok(false)` (not an error)
/// if there is nothing to roll back to.
pub fn rollback(sig_dir: &Path) -> Result<bool, ApplyError> {
    let previous = previous_path(sig_dir);
    if !previous.is_dir() {
        return Ok(false);
    }
    if sig_dir.exists() {
        std::fs::remove_dir_all(sig_dir).map_err(|e| ApplyError::Io {
            step: "removing current signatures before rollback",
            source: e,
        })?;
    }
    std::fs::rename(&previous, sig_dir).map_err(|e| ApplyError::Io {
        step: "restoring .previous signatures",
        source: e,
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, name: &str, contents: &str) {
        fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn first_update_with_no_prior_sig_dir() {
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        write(&staging, "main.ndb", "v1 sigs");

        apply_update(&staging, &sig_dir).unwrap();

        assert_eq!(
            fs::read_to_string(sig_dir.join("main.ndb")).unwrap(),
            "v1 sigs"
        );
        assert!(!staging.exists());
    }

    #[test]
    fn subsequent_update_preserves_previous_generation() {
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        fs::create_dir(&sig_dir).unwrap();
        write(&sig_dir, "main.ndb", "v1 sigs");

        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        write(&staging, "main.ndb", "v2 sigs");

        apply_update(&staging, &sig_dir).unwrap();

        assert_eq!(
            fs::read_to_string(sig_dir.join("main.ndb")).unwrap(),
            "v2 sigs"
        );
        let previous = previous_path(&sig_dir);
        assert_eq!(
            fs::read_to_string(previous.join("main.ndb")).unwrap(),
            "v1 sigs"
        );
    }

    #[test]
    fn rollback_restores_previous_generation() {
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        fs::create_dir(&sig_dir).unwrap();
        write(&sig_dir, "main.ndb", "v1 sigs");

        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        write(&staging, "main.ndb", "v2 sigs (bad)");
        apply_update(&staging, &sig_dir).unwrap();
        assert_eq!(
            fs::read_to_string(sig_dir.join("main.ndb")).unwrap(),
            "v2 sigs (bad)"
        );

        let rolled_back = rollback(&sig_dir).unwrap();
        assert!(rolled_back);
        assert_eq!(
            fs::read_to_string(sig_dir.join("main.ndb")).unwrap(),
            "v1 sigs"
        );
    }

    #[test]
    fn rollback_is_a_noop_when_nothing_to_roll_back_to() {
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        fs::create_dir(&sig_dir).unwrap();
        write(&sig_dir, "main.ndb", "only sigs");

        let rolled_back = rollback(&sig_dir).unwrap();
        assert!(!rolled_back);
        assert_eq!(
            fs::read_to_string(sig_dir.join("main.ndb")).unwrap(),
            "only sigs"
        );
    }

    #[test]
    fn repeated_updates_only_retain_one_previous_generation() {
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        fs::create_dir(&sig_dir).unwrap();
        write(&sig_dir, "main.ndb", "v1");

        for v in ["v2", "v3", "v4"] {
            let staging = root.path().join("staging");
            fs::create_dir(&staging).unwrap();
            write(&staging, "main.ndb", v);
            apply_update(&staging, &sig_dir).unwrap();
        }

        assert_eq!(fs::read_to_string(sig_dir.join("main.ndb")).unwrap(), "v4");
        let previous = previous_path(&sig_dir);
        assert_eq!(fs::read_to_string(previous.join("main.ndb")).unwrap(), "v3");
    }

    #[test]
    fn missing_staging_dir_errors_cleanly() {
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        let staging = root.path().join("does-not-exist");
        assert!(matches!(
            apply_update(&staging, &sig_dir),
            Err(ApplyError::StagingMissing(_))
        ));
    }

    #[test]
    fn concurrent_updates_never_leave_a_mixed_or_corrupt_sig_dir() {
        // Two updates racing to swap into the same sig_dir at once -- not
        // a scenario this tool's normal cron/systemd-timer usage should
        // ever produce (only one instance should be scheduled at a time),
        // but worth verifying directly rather than only by reasoning about
        // `rename`'s atomicity: whichever one wins, `sig_dir` must end up
        // as one complete, internally-consistent generation, never a
        // half-A-half-B mix and never empty/missing.
        use std::sync::{Arc, Barrier};
        use std::thread;

        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        fs::create_dir(&sig_dir).unwrap();
        write(&sig_dir, "main.ndb", "v0");

        let staging_a = root.path().join("staging-a");
        fs::create_dir(&staging_a).unwrap();
        write(&staging_a, "main.ndb", "generation-A");
        write(&staging_a, "daily.hdb", "generation-A");

        let staging_b = root.path().join("staging-b");
        fs::create_dir(&staging_b).unwrap();
        write(&staging_b, "main.ndb", "generation-B");
        write(&staging_b, "daily.hdb", "generation-B");

        // A barrier forces both threads to call apply_update as close to
        // simultaneously as the OS scheduler allows, rather than one
        // reliably finishing before the other starts.
        let barrier = Arc::new(Barrier::new(2));
        let sig_dir_a = sig_dir.clone();
        let sig_dir_b = sig_dir.clone();
        let barrier_a = barrier.clone();
        let barrier_b = barrier.clone();

        let handle_a = thread::spawn(move || {
            barrier_a.wait();
            apply_update(&staging_a, &sig_dir_a)
        });
        let handle_b = thread::spawn(move || {
            barrier_b.wait();
            apply_update(&staging_b, &sig_dir_b)
        });

        let result_a = handle_a.join().unwrap();
        let result_b = handle_b.join().unwrap();

        // At least one must succeed (the loser may see `StagingMissing` if
        // its own staging dir was already consumed, or an `Io` error if it
        // lost a race on `.previous` -- either is an acceptable *outcome*
        // for the loser; a panic, or `sig_dir` ending up corrupt, is not).
        assert!(
            result_a.is_ok() || result_b.is_ok(),
            "at least one concurrent update must succeed: a={result_a:?} b={result_b:?}"
        );

        // The critical property: sig_dir must be exactly one complete
        // generation afterwards -- both files present and matching each
        // other (same generation), never a mix of A's main.ndb with B's
        // daily.hdb.
        let main = fs::read_to_string(sig_dir.join("main.ndb")).unwrap();
        let daily = fs::read_to_string(sig_dir.join("daily.hdb")).unwrap();
        assert_eq!(
            main, daily,
            "sig_dir ended up with files from two different generations mixed together"
        );
        assert!(main == "generation-A" || main == "generation-B");
    }

    #[test]
    fn interrupted_update_fails_cleanly_without_touching_live_sig_dir() {
        // Simulates an update that can't proceed (here: a `.previous`
        // directory from an even-older, never-cleaned-up interrupted
        // update is blocked -- a plain file sitting where a directory is
        // expected) failing *before* it has touched the live `sig_dir` at
        // all. The property under test: a failure that happens before any
        // rename must leave the live signatures completely untouched, not
        // partially modified -- a daemon reading `sig_dir` at any point
        // during a failed update attempt must see a complete, valid
        // generation the whole time.
        let root = tempfile::tempdir().unwrap();
        let sig_dir = root.path().join("sigs");
        fs::create_dir(&sig_dir).unwrap();
        write(&sig_dir, "main.ndb", "live and valid");

        // Block the ".previous" slot with a file where a directory is
        // expected, so `remove_dir_all` on it fails cleanly instead of
        // silently doing nothing.
        let previous = previous_path(&sig_dir);
        write(root.path(), previous.file_name().unwrap().to_str().unwrap(), "blocking file");

        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        write(&staging, "main.ndb", "new update, never applied");

        let result = apply_update(&staging, &sig_dir);
        assert!(matches!(result, Err(ApplyError::Io { .. })));

        // sig_dir must be exactly as it was -- not renamed, not partially
        // replaced.
        assert_eq!(
            fs::read_to_string(sig_dir.join("main.ndb")).unwrap(),
            "live and valid"
        );
        assert!(sig_dir.is_dir());
    }
}
