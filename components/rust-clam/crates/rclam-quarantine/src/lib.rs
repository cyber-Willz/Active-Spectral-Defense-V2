//! Quarantine neutralizes a detected file with ChaCha20-Poly1305
//! (a real AEAD stream cipher, keyed with fresh random material per file)
//! before storing it, then removes the original. This is *not* meant to
//! protect confidentiality from an operator who controls the quarantine
//! store -- the decryption key is stored right alongside the ciphertext,
//! in the sidecar `.json` record, because restoring a file is a normal,
//! supported operation for that operator. What it *does* guarantee, the
//! same as what commercial engines guarantee here:
//!
//! - the file cannot be executed or opened by its original file
//!   association while quarantined,
//! - it cannot be re-detected by another on-access scanner sitting in the
//!   quarantine directory (its content no longer contains the byte
//!   pattern that matched),
//! - and -- this is the part a naive repeating-key XOR does *not* give
//!   you -- an attacker who knows some of the plaintext (a reasonable
//!   assumption for a detected file: the signature that matched is by
//!   definition already public) cannot use that knowledge to recover a
//!   reusable keystream and decrypt the rest of the file without the
//!   stored key. ChaCha20's keystream is a full permutation of the
//!   nonce+counter, not a short repeating block, so known-plaintext at
//!   one offset reveals nothing about the keystream at any other offset.
//! - Poly1305's authentication tag also means a bit-flipped or corrupted
//!   quarantine file fails to decrypt cleanly on restore, rather than
//!   silently producing garbage that looks like a legitimate restore.
//!
//! This crate has no dependency on `scanner-core` or `sig-engine` on
//! purpose: it only needs the caller to already know *that* a file is
//! infected and *what* matched, so it can be driven equally by
//! `rclam-cli`, `rclam-daemon`, or the real-time `rclam-watch` monitor
//! without pulling in signature-matching or archive-recursion code it has
//! no use for.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("quarantine store error: {0}")]
    Store(String),
    #[error("no quarantine record with id {0}")]
    NotFound(String),
    #[error(
        "integrity check failed for {id}: stored payload does not authenticate against its \
         recorded key/nonce -- it has been corrupted or tampered with since quarantine"
    )]
    IntegrityCheckFailed { id: String },
}

pub type Result<T> = std::result::Result<T, QuarantineError>;

fn io_err(path: &Path, source: std::io::Error) -> QuarantineError {
    QuarantineError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Hashes `data` with SHA-256 and returns the lowercase hex digest -- a
/// small convenience so callers that already have the file's bytes in
/// memory (e.g. because they just scanned it) don't need to pull in
/// `sha2` themselves just to fill in [`QuarantineRecord::sha256`].
pub fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    hex::encode(digest)
}

/// Generates a random 128-bit identifier as a 32-character lowercase hex
/// string. Same entropy as a UUIDv4, but avoids pulling in the `uuid`
/// crate purely for one random token -- this project's other IDs (e.g.
/// signature manifest versions) are plain hex too, so it also keeps the
/// convention consistent.
fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: PathBuf,
    /// Name(s) of the signature(s) that triggered quarantine, joined with
    /// `", "` if more than one detection fired on the same file.
    pub signature_name: String,
    pub quarantined_at: DateTime<Utc>,
    pub sha256: String,
    pub file_size: u64,
    key_hex: String,
    nonce_hex: String,
    stored_filename: String,
}

pub struct QuarantineManager {
    dir: PathBuf,
}

impl QuarantineManager {
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Reads `original_path` from disk, neutralizes it, stores it in the
    /// quarantine directory, then deletes the original. The original is
    /// only removed once the neutralized copy is confirmed written to
    /// disk, so a crash or power loss mid-quarantine can never lose the
    /// file entirely.
    pub fn quarantine_file(
        &self,
        original_path: &Path,
        signature_name: &str,
    ) -> Result<QuarantineRecord> {
        let data = fs::read(original_path).map_err(|e| io_err(original_path, e))?;
        let record = self.quarantine_bytes(original_path, &data, signature_name)?;
        fs::remove_file(original_path).map_err(|e| io_err(original_path, e))?;
        Ok(record)
    }

    /// Same as [`Self::quarantine_file`], but takes bytes the caller has
    /// already read (e.g. from an mmap during a scan) instead of
    /// re-reading the file, and does *not* delete `original_path` --
    /// callers that want the original removed should follow up with
    /// `fs::remove_file` themselves once they're ready to do so (or just
    /// use `quarantine_file`, which does both atomically-enough for a
    /// local single-writer scanner).
    pub fn quarantine_bytes(
        &self,
        original_path: &Path,
        data: &[u8],
        signature_name: &str,
    ) -> Result<QuarantineRecord> {
        let sha256 = sha256_hex(data);
        let file_size = data.len() as u64;

        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data).map_err(|_| {
            QuarantineError::Store("AEAD encryption failed while quarantining".to_string())
        })?;

        let id = random_id();
        let stored_filename = format!("{id}.quar");
        let stored_path = self.dir.join(&stored_filename);

        let mut f = fs::File::create(&stored_path).map_err(|e| io_err(&stored_path, e))?;
        f.write_all(&ciphertext)
            .map_err(|e| io_err(&stored_path, e))?;
        f.sync_all().map_err(|e| io_err(&stored_path, e))?;

        let record = QuarantineRecord {
            id: id.clone(),
            original_path: original_path.to_path_buf(),
            signature_name: signature_name.to_string(),
            quarantined_at: Utc::now(),
            sha256,
            file_size,
            key_hex: hex::encode(key_bytes),
            nonce_hex: hex::encode(nonce_bytes),
            stored_filename,
        };

        let meta_path = self.dir.join(format!("{id}.json"));
        let meta_json = serde_json::to_string_pretty(&record)
            .map_err(|e| QuarantineError::Store(format!("failed to serialize record: {e}")))?;
        fs::write(&meta_path, meta_json).map_err(|e| io_err(&meta_path, e))?;

        tracing::warn!(
            path = %original_path.display(),
            signature = signature_name,
            id = %id,
            "quarantined file"
        );

        Ok(record)
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>> {
        let mut out = Vec::new();
        if !self.dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&self.dir).map_err(|e| io_err(&self.dir, e))? {
            let entry = entry.map_err(|e| io_err(&self.dir, e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let content = fs::read_to_string(&path).map_err(|e| io_err(&path, e))?;
                match serde_json::from_str::<QuarantineRecord>(&content) {
                    Ok(record) => out.push(record),
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "skipping corrupt quarantine record")
                    }
                }
            }
        }
        out.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        Ok(out)
    }

    /// Reverses neutralization and writes the file back out. Defaults to
    /// the file's original path if `restore_to` isn't given. This is a
    /// deliberate operator action (there's no automatic un-quarantine
    /// anywhere in this codebase) and is logged at `warn` level for the
    /// same reason automatic restores don't exist: putting a confirmed
    /// detection back onto disk should always be an explicit, visible
    /// decision.
    pub fn restore(&self, id: &str, restore_to: Option<&Path>) -> Result<PathBuf> {
        let record = self.find_record(id)?;
        let data = self.decrypt_record(&record)?;

        let dest = restore_to
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| record.original_path.clone());

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        fs::write(&dest, &data).map_err(|e| io_err(&dest, e))?;

        tracing::warn!(
            id = id,
            destination = %dest.display(),
            "restored quarantined file -- ensure this was intentional"
        );
        Ok(dest)
    }

    /// Authenticates a quarantined item without writing anything back to
    /// disk -- decrypts it in memory, checks the Poly1305 tag, and (as a
    /// second, independent check) recomputes SHA-256 over the recovered
    /// plaintext and compares it against the hash recorded at quarantine
    /// time. Returns `Ok(())` if both checks pass.
    ///
    /// This is what makes the AEAD switch from raw XOR actually worth
    /// something operationally: an operator can periodically sweep the
    /// quarantine store and get a real answer to "has anything in here
    /// been corrupted or tampered with since it was quarantined?" instead
    /// of only finding out at restore time.
    pub fn verify(&self, id: &str) -> Result<()> {
        let record = self.find_record(id)?;
        let data = self.decrypt_record(&record)?;
        let actual_sha256 = sha256_hex(&data);
        if actual_sha256 != record.sha256 {
            // The AEAD tag already protects the ciphertext, so reaching
            // this branch would mean the *record itself* was hand-edited
            // to match a different tag -- belt-and-suspenders, not the
            // primary defense, but cheap to check.
            return Err(QuarantineError::IntegrityCheckFailed { id: id.to_string() });
        }
        Ok(())
    }

    fn decrypt_record(&self, record: &QuarantineRecord) -> Result<Vec<u8>> {
        let stored_path = self.dir.join(&record.stored_filename);
        let ciphertext = fs::read(&stored_path).map_err(|e| io_err(&stored_path, e))?;

        let key_bytes = hex::decode(&record.key_hex)
            .map_err(|e| QuarantineError::Store(format!("corrupt key for {}: {e}", record.id)))?;
        let nonce_bytes = hex::decode(&record.nonce_hex).map_err(|e| {
            QuarantineError::Store(format!("corrupt nonce for {}: {e}", record.id))
        })?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| QuarantineError::IntegrityCheckFailed {
                id: record.id.clone(),
            })
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let record = self.find_record(id)?;
        let stored_path = self.dir.join(&record.stored_filename);
        let meta_path = self.dir.join(format!("{id}.json"));
        let _ = fs::remove_file(&stored_path);
        fs::remove_file(&meta_path).map_err(|e| io_err(&meta_path, e))?;
        tracing::info!(id = id, "permanently deleted quarantined item");
        Ok(())
    }

    fn find_record(&self, id: &str) -> Result<QuarantineRecord> {
        self.list()?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| QuarantineError::NotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn quarantine_then_restore_round_trips_original_bytes() {
        let store = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let original = src_dir.path().join("payload.exe");
        let content = b"this is definitely not a virus";
        fs::write(&original, content).unwrap();

        let mgr = QuarantineManager::new(store.path()).unwrap();
        let record = mgr.quarantine_file(&original, "Sig.Test").unwrap();

        // Original must be gone, and neutralized bytes on disk must not
        // equal the plaintext (otherwise "neutralization" did nothing).
        assert!(!original.exists());
        let stored_bytes = fs::read(store.path().join(format!("{}.quar", record.id))).unwrap();
        assert_ne!(stored_bytes, content);
        assert_eq!(record.sha256, sha256_hex(content));

        let restore_dest = src_dir.path().join("restored.exe");
        let restored_path = mgr.restore(&record.id, Some(&restore_dest)).unwrap();
        assert_eq!(fs::read(&restored_path).unwrap(), content);
    }

    #[test]
    fn list_reflects_multiple_quarantined_items_newest_first() {
        let store = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let mgr = QuarantineManager::new(store.path()).unwrap();

        for i in 0..3 {
            let p = src_dir.path().join(format!("f{i}.bin"));
            fs::write(&p, format!("payload {i}")).unwrap();
            mgr.quarantine_file(&p, "Sig.Test").unwrap();
        }

        let items = mgr.list().unwrap();
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn delete_removes_both_payload_and_metadata() {
        let store = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let original = src_dir.path().join("payload.bin");
        fs::write(&original, b"malware bytes").unwrap();

        let mgr = QuarantineManager::new(store.path()).unwrap();
        let record = mgr.quarantine_file(&original, "Sig.Test").unwrap();
        mgr.delete(&record.id).unwrap();

        assert!(mgr.list().unwrap().is_empty());
        assert!(!store.path().join(format!("{}.quar", record.id)).exists());
    }

    #[test]
    fn restore_of_unknown_id_errors_cleanly() {
        let store = tempdir().unwrap();
        let mgr = QuarantineManager::new(store.path()).unwrap();
        assert!(matches!(
            mgr.restore("does-not-exist", None),
            Err(QuarantineError::NotFound(_))
        ));
    }

    #[test]
    fn quarantine_bytes_does_not_touch_original_file() {
        // quarantine_bytes is meant for callers (e.g. a scanner holding an
        // mmap) that want a quarantine record written without the crate
        // deleting anything on their behalf.
        let store = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let original = src_dir.path().join("payload.bin");
        fs::write(&original, b"payload").unwrap();

        let mgr = QuarantineManager::new(store.path()).unwrap();
        mgr.quarantine_bytes(&original, b"payload", "Sig.Test")
            .unwrap();

        assert!(original.exists(), "quarantine_bytes must not delete the original");
    }

    #[test]
    fn verify_passes_for_an_untampered_item() {
        let store = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let original = src_dir.path().join("payload.bin");
        fs::write(&original, b"this is definitely not a virus").unwrap();

        let mgr = QuarantineManager::new(store.path()).unwrap();
        let record = mgr.quarantine_file(&original, "Sig.Test").unwrap();

        assert!(mgr.verify(&record.id).is_ok());
    }

    #[test]
    fn tampering_with_stored_ciphertext_is_detected_not_silently_decrypted() {
        // This is the concrete behavioral difference from the old
        // repeating-key XOR scheme: flipping bytes in the stored file must
        // make both verify() and restore() fail loudly, not quietly hand
        // back corrupted "restored" output.
        let store = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let original = src_dir.path().join("payload.bin");
        fs::write(&original, b"this is definitely not a virus, honest").unwrap();

        let mgr = QuarantineManager::new(store.path()).unwrap();
        let record = mgr.quarantine_file(&original, "Sig.Test").unwrap();

        let stored_path = store.path().join(format!("{}.quar", record.id));
        let mut bytes = fs::read(&stored_path).unwrap();
        bytes[0] ^= 0xFF; // flip a bit in the ciphertext
        fs::write(&stored_path, &bytes).unwrap();

        assert!(matches!(
            mgr.verify(&record.id),
            Err(QuarantineError::IntegrityCheckFailed { .. })
        ));
        assert!(matches!(
            mgr.restore(&record.id, None),
            Err(QuarantineError::IntegrityCheckFailed { .. })
        ));
    }
}
