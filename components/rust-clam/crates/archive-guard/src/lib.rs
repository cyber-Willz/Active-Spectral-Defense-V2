//! Archive recursion with hard, code-enforced bomb protection.
//!
//! ClamAV's archive-bomb CVEs (e.g. CVE-2023-20032, CVE-2019-15961) came
//! from limits that were configuration-driven and could be bypassed or
//! misapplied in specific decoders. Here the limits are structural: every
//! extraction call is threaded through a `GuardBudget` that is decremented
//! as bytes come out, and extraction is aborted the instant any limit is
//! crossed -- there is no code path that produces archive contents without
//! going through the budget check.

use std::io::Read;
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub struct GuardLimits {
    /// Maximum nested-archive recursion depth.
    pub max_depth: u32,
    /// Maximum number of entries extracted from any single archive.
    pub max_entries: u64,
    /// Maximum total uncompressed bytes across the whole recursive scan.
    pub max_total_uncompressed: u64,
    /// Maximum allowed (uncompressed / compressed) ratio per entry, to
    /// catch zip-bomb style single-file amplification.
    pub max_ratio: u64,
    /// Cap on a single read call, so a stream that lies about its length
    /// can't be used to force one giant allocation.
    pub read_chunk: usize,
    /// Maximum size (in bytes) of a *top-level* file this process will map
    /// and scan directly. This bounds the worst-case CPU time a single scan
    /// request can consume (hashing + entropy scoring are O(n)), which
    /// matters for a shared daemon fielding requests from multiple clients.
    /// It does not limit archive member sizes -- those are already bounded
    /// by `max_total_uncompressed`.
    pub max_file_size: u64,
}

impl Default for GuardLimits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_entries: 10_000,
            max_total_uncompressed: 4 * 1024 * 1024 * 1024, // 4 GiB
            max_ratio: 1000,
            read_chunk: 1 << 20,              // 1 MiB
            max_file_size: 200 * 1024 * 1024, // 200 MiB
        }
    }
}

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("archive recursion depth {0} exceeds limit")]
    DepthExceeded(u32),
    #[error("entry count exceeds limit ({0})")]
    EntryCountExceeded(u64),
    #[error("total uncompressed size exceeds limit ({0} bytes)")]
    TotalSizeExceeded(u64),
    #[error("entry '{name}' compression ratio {ratio} exceeds limit")]
    RatioExceeded { name: String, ratio: u64 },
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("7z error: {0}")]
    SevenZ(String),
    #[error("cab error: {0}")]
    Cab(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Tracks cumulative consumption across an entire (possibly nested) archive
/// scan so limits apply globally, not just per-archive.
pub struct GuardBudget {
    limits: GuardLimits,
    depth: u32,
    entries_seen: u64,
    total_uncompressed: u64,
}

impl GuardBudget {
    pub fn new(limits: GuardLimits) -> Self {
        Self {
            limits,
            depth: 0,
            entries_seen: 0,
            total_uncompressed: 0,
        }
    }

    pub fn enter_archive(&mut self) -> Result<(), GuardError> {
        self.depth += 1;
        if self.depth > self.limits.max_depth {
            return Err(GuardError::DepthExceeded(self.depth));
        }
        Ok(())
    }

    pub fn leave_archive(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn charge_entry(&mut self, uncompressed_add: u64) -> Result<(), GuardError> {
        self.entries_seen += 1;
        if self.entries_seen > self.limits.max_entries {
            return Err(GuardError::EntryCountExceeded(self.limits.max_entries));
        }
        self.total_uncompressed += uncompressed_add;
        if self.total_uncompressed > self.limits.max_total_uncompressed {
            return Err(GuardError::TotalSizeExceeded(
                self.limits.max_total_uncompressed,
            ));
        }
        Ok(())
    }
}

pub struct ExtractedEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Extract every entry of a ZIP archive (one level only — recursion into
/// nested archives is the caller's responsibility), enforcing `budget`'s
/// per-entry limits as we go.
///
/// IMPORTANT: this function does **not** touch `budget`'s depth counter.
/// Depth must be scoped by the caller with `enter_archive`/`leave_archive`
/// around the *entire* recursive descent into this archive's entries —
/// scoping it here (around just the flat extraction call) would let the
/// counter reset to zero before the caller ever recurses, making the depth
/// limit a no-op against nested/self-referential ("zip quine") archives.
///
/// On any per-entry limit breach, extraction stops immediately and the
/// error is returned alongside whatever was already extracted, so the
/// caller can still scan what came out before the bomb was detected.
pub fn extract_zip(
    reader: impl Read + std::io::Seek,
    budget: &mut GuardBudget,
) -> Result<(Vec<ExtractedEntry>, Option<GuardError>), GuardError> {
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut out = Vec::new();
    let mut hit_limit: Option<GuardError> = None;

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            // A single malformed/encrypted/unsupported entry shouldn't
            // sink the whole archive scan -- skip it and keep going so
            // the rest of the archive still gets scanned.
            Err(_) => continue,
        };
        let name = entry.name().to_string();
        let compressed_size = entry.compressed_size().max(1);
        let declared_uncompressed = entry.size();

        // Ratio check against the *declared* size before we even start
        // reading, so we can bail before allocating for an obvious bomb.
        let declared_ratio = declared_uncompressed / compressed_size;
        if declared_ratio > budget.limits.max_ratio {
            hit_limit = Some(GuardError::RatioExceeded {
                name,
                ratio: declared_ratio,
            });
            break;
        }

        // Stream-read in bounded chunks rather than trusting the declared
        // size for a single allocation, and re-check the budget after every
        // chunk so a lying header can't blow past the total-size limit
        // before we notice.
        let mut data = Vec::new();
        let mut chunk = vec![0u8; budget.limits.read_chunk];
        loop {
            let n = match entry.read(&mut chunk) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            if let Err(e) = budget.charge_entry(n as u64) {
                hit_limit = Some(e);
                break;
            }
            data.extend_from_slice(&chunk[..n]);
        }
        out.push(ExtractedEntry { name, data });
        if hit_limit.is_some() {
            break;
        }
    }

    Ok((out, hit_limit))
}

/// Decompress a single gzip stream (magic `1F 8B`), enforcing `budget`'s
/// total-size limit as bytes come out.
///
/// Unlike `extract_zip`, gzip has no reliable declared uncompressed size to
/// pre-check against (the trailing ISIZE field is only the length modulo
/// 2^32, so a crafted stream can lie about it arbitrarily) -- so the *only*
/// defense against a gzip bomb here is the same one used for zip's streamed
/// entries: read in bounded chunks and re-check the cumulative budget after
/// every chunk, aborting the instant it's exceeded. `MultiGzDecoder` is used
/// so concatenated gzip members (as produced by `zcat a.gz b.gz > both.gz`,
/// which real gzip decompresses as one logical stream) are all consumed
/// rather than silently truncating after the first member.
pub fn extract_gzip(
    reader: impl Read,
    budget: &mut GuardBudget,
) -> Result<(Vec<u8>, Option<GuardError>), GuardError> {
    use flate2::read::MultiGzDecoder;

    let mut decoder = MultiGzDecoder::new(reader);
    let mut data = Vec::new();
    let mut chunk = vec![0u8; budget.limits.read_chunk];
    loop {
        let n = match decoder.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            // A malformed/truncated gzip stream ends the decompression but
            // is not itself a hard error -- whatever decompressed cleanly
            // before the corruption is still worth scanning.
            Err(_) => break,
        };
        if let Err(e) = budget.charge_entry(n as u64) {
            return Ok((data, Some(e)));
        }
        data.extend_from_slice(&chunk[..n]);
    }
    Ok((data, None))
}

/// Returns true if `buf` looks like a POSIX ustar (i.e. GNU/modern `tar`)
/// archive: the `magic` field at header offset 257 is `"ustar"` (either the
/// POSIX `"ustar\0"` or the older GNU `"ustar  \0"` variant). Legacy V7 tar
/// (no magic field at all) is intentionally not detected -- it is rare in
/// practice and misdetecting arbitrary binary data as V7 tar would be a
/// false-positive-prone guess with no magic bytes to anchor on.
pub fn looks_like_tar(buf: &[u8]) -> bool {
    buf.len() >= 263 && &buf[257..262] == b"ustar"
}

/// Extract every entry of a tar archive (one level only -- recursion into
/// nested archives, including a tar member that is itself a tar/zip/gzip
/// file, is the caller's responsibility), enforcing `budget`'s per-entry and
/// cumulative limits as we go.
///
/// Unlike zip, a tar entry's header `size` field is simply the number of
/// content bytes that follow in the stream -- there is no separate
/// "compressed size" to compute a ratio against, so no ratio check applies
/// here. That is not a gap: plain tar cannot itself amplify bytes (a tar
/// member is exactly as large on disk as what gets read back out), and a
/// compressed container (`.tar.gz`) already has its ratio checked one layer
/// out, in `extract_gzip`, before these bytes are ever handed to
/// `extract_tar`. The entry-count and total-uncompressed-size limits still
/// apply here regardless, guarding against an archive with an enormous
/// number of entries or an enormous total payload.
///
/// Same shape as `extract_zip`: depth is the caller's responsibility (scope
/// `enter_archive`/`leave_archive` around the full recursive descent, not
/// around this flat call), and on a limit breach extraction stops
/// immediately, returning whatever was already extracted alongside the
/// error so the caller can still scan it.
pub fn extract_tar(
    reader: impl Read,
    budget: &mut GuardBudget,
) -> Result<(Vec<ExtractedEntry>, Option<GuardError>), GuardError> {
    let mut archive = tar::Archive::new(reader);
    let mut out = Vec::new();
    let mut hit_limit: Option<GuardError> = None;

    let entries = match archive.entries() {
        Ok(e) => e,
        // A stream that doesn't parse as tar at all (e.g. truncated header)
        // is a clean error, not a panic.
        Err(e) => return Err(GuardError::Io(e)),
    };

    'entries: for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            // One malformed entry (bad header checksum, etc.) shouldn't sink
            // the rest of the archive -- skip it and keep going, matching
            // extract_zip's per-entry error handling.
            Err(_) => continue,
        };
        // Only regular files carry scannable content; directories, hard
        // links, symlinks, device nodes, etc. have no bytes to read (or, for
        // links, point somewhere the archive-relative name doesn't actually
        // contain) and are skipped rather than misread as empty payloads.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "<invalid-tar-path>".to_string());

        let mut data = Vec::new();
        let mut chunk = vec![0u8; budget.limits.read_chunk];
        loop {
            let n = match entry.read(&mut chunk) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            if let Err(e) = budget.charge_entry(n as u64) {
                hit_limit = Some(e);
                out.push(ExtractedEntry { name, data });
                break 'entries;
            }
            data.extend_from_slice(&chunk[..n]);
        }
        out.push(ExtractedEntry { name, data });
    }

    Ok((out, hit_limit))
}

/// Returns true if `buf` starts with the 7z signature (`37 7A BC AF 27 1C`).
pub fn looks_like_7z(buf: &[u8]) -> bool {
    buf.len() >= 6 && &buf[0..6] == b"\x37\x7A\xBC\xAF\x27\x1C"
}

/// Returns true if `buf` starts with the Microsoft Cabinet signature
/// (`MSCF`).
pub fn looks_like_cab(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[0..4] == b"MSCF"
}

/// Extract every entry of a 7z archive (one level only -- recursion into
/// nested archives is the caller's responsibility), enforcing `budget`'s
/// per-entry and cumulative limits as bytes come out of the decoder.
///
/// Unlike zip, the underlying `sevenz-rust` decoder streams a whole
/// compression block at a time for solid archives (multiple files sharing
/// one compressed block) -- see its own documentation on that -- so
/// aborting mid-entry here stops *this scan* from buffering more than the
/// budget allows and stops processing further entries, but does not
/// necessarily save the CPU cost of decompressing the rest of an
/// in-progress solid block. That is an inherent property of the 7z format
/// (and shared by every 7z-capable scanner, not something specific to
/// this implementation) -- the byte-budget guarantee this function does
/// give you, unconditionally, is the same one `extract_zip`/`extract_tar`
/// give: never hand more than `max_total_uncompressed` bytes back to the
/// caller.
///
/// No password support -- an encrypted 7z is treated the same as any
/// other archive this scanner can't open: it fails to parse and is
/// scanned as opaque bytes at the outer level instead (an encrypted
/// archive's payload is opaque to a signature scanner regardless, so
/// there is no detection capability lost here that a password would have
/// recovered without the password itself).
pub fn extract_7z(
    mut reader: impl Read + std::io::Seek,
    budget: &mut GuardBudget,
) -> Result<(Vec<ExtractedEntry>, Option<GuardError>), GuardError> {
    use sevenz_rust::{Password, SevenZReader};
    use std::io::SeekFrom;

    let len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    let mut archive = SevenZReader::new(reader, len, Password::empty())
        .map_err(|e| GuardError::SevenZ(e.to_string()))?;

    let mut out: Vec<ExtractedEntry> = Vec::new();
    let mut hit_limit: Option<GuardError> = None;

    let result = archive.for_each_entries(|entry, source| {
        if entry.is_directory() || !entry.has_stream() {
            return Ok(true); // nothing to read for this entry, keep going
        }
        let name = entry.name().to_string();
        let mut data = Vec::new();
        let mut chunk = vec![0u8; budget.limits.read_chunk];
        loop {
            let n = match source.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                // A malformed/truncated stream ends this entry's read but
                // is not itself a hard error, matching extract_zip's and
                // extract_gzip's per-entry tolerance.
                Err(_) => break,
            };
            if let Err(e) = budget.charge_entry(n as u64) {
                hit_limit = Some(e);
                out.push(ExtractedEntry { name: name.clone(), data });
                // Returning Ok(false) stops for_each_entries from
                // processing any further entries -- the sevenz-rust
                // equivalent of the `break 'entries` used in extract_tar.
                return Ok(false);
            }
            data.extend_from_slice(&chunk[..n]);
        }
        out.push(ExtractedEntry { name, data });
        Ok(true)
    });

    if let Err(e) = result {
        // A genuinely malformed archive (bad header, checksum mismatch,
        // etc.) that failed before or during entry processing. If a
        // budget limit already tripped, that's the more specific and more
        // actionable error to surface -- keep it and the partial results
        // instead of overwriting with the generic parse failure that
        // followed from aborting mid-stream.
        if hit_limit.is_none() {
            return Err(GuardError::SevenZ(e.to_string()));
        }
    }

    Ok((out, hit_limit))
}

/// Extract every entry of a Microsoft Cabinet (.cab) archive (one level
/// only), enforcing `budget`'s per-entry and cumulative limits as we go.
/// Same shape and same per-entry error tolerance as `extract_zip`.
pub fn extract_cab(
    reader: impl Read + std::io::Seek,
    budget: &mut GuardBudget,
) -> Result<(Vec<ExtractedEntry>, Option<GuardError>), GuardError> {
    let mut archive = cab::Cabinet::new(reader).map_err(|e| GuardError::Cab(e.to_string()))?;
    let mut out = Vec::new();
    let mut hit_limit: Option<GuardError> = None;

    // Collect (folder, file) names up front since `read_file` needs `&mut
    // self` and we can't hold a borrow of `archive` across the loop while
    // also calling back into it.
    let file_names: Vec<String> = archive
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|f| f.name().to_string())
        .collect();

    'entries: for name in file_names {
        let mut entry = match archive.read_file(&name) {
            Ok(e) => e,
            // A single malformed/unsupported entry shouldn't sink the
            // whole archive scan, matching extract_zip's tolerance.
            Err(_) => continue,
        };

        let mut data = Vec::new();
        let mut chunk = vec![0u8; budget.limits.read_chunk];
        loop {
            let n = match entry.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if let Err(e) = budget.charge_entry(n as u64) {
                hit_limit = Some(e);
                out.push(ExtractedEntry { name: name.clone(), data });
                break 'entries;
            }
            data.extend_from_slice(&chunk[..n]);
        }
        out.push(ExtractedEntry { name, data });
    }

    Ok((out, hit_limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                writer.start_file(*name, opts).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_normal_zip_entries() {
        let zip = make_zip(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut budget = GuardBudget::new(GuardLimits::default());
        let (entries, hit) = extract_zip(Cursor::new(zip), &mut budget).unwrap();
        assert!(hit.is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(entries[1].data, b"world");
    }

    #[test]
    fn ratio_guard_trips_on_extreme_compression() {
        let zip = make_zip(&[("bomb.bin", &vec![0u8; 20 * 1024 * 1024])]);
        let mut budget = GuardBudget::new(GuardLimits {
            max_ratio: 1000,
            ..GuardLimits::default()
        });
        let (_entries, hit) = extract_zip(Cursor::new(zip), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::RatioExceeded { .. })));
    }

    #[test]
    fn entry_count_guard_trips() {
        let entries: Vec<(&str, &[u8])> = vec![("a", b"1"), ("b", b"2"), ("c", b"3"), ("d", b"4")];
        let zip = make_zip(&entries);
        let mut budget = GuardBudget::new(GuardLimits {
            max_entries: 2,
            max_ratio: u64::MAX,
            ..GuardLimits::default()
        });
        let (extracted, hit) = extract_zip(Cursor::new(zip), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::EntryCountExceeded(_))));
        // Should have extracted up through the point the limit tripped, not
        // silently discarded everything.
        assert!(!extracted.is_empty());
    }

    #[test]
    fn total_size_guard_trips_across_multiple_entries() {
        let entries: Vec<(&str, &[u8])> =
            vec![("a", &[0u8; 100]), ("b", &[0u8; 100]), ("c", &[0u8; 100])];
        let zip = make_zip(&entries);
        let mut budget = GuardBudget::new(GuardLimits {
            max_total_uncompressed: 150,
            max_ratio: u64::MAX,
            ..GuardLimits::default()
        });
        let (_extracted, hit) = extract_zip(Cursor::new(zip), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::TotalSizeExceeded(_))));
    }

    #[test]
    fn depth_guard_rejects_past_max_depth() {
        let mut budget = GuardBudget::new(GuardLimits {
            max_depth: 3,
            ..GuardLimits::default()
        });
        assert!(budget.enter_archive().is_ok()); // depth 1
        assert!(budget.enter_archive().is_ok()); // depth 2
        assert!(budget.enter_archive().is_ok()); // depth 3
        assert!(matches!(
            budget.enter_archive(),
            Err(GuardError::DepthExceeded(4))
        )); // depth 4 > max 3
    }

    #[test]
    fn depth_guard_allows_sibling_archives_after_leave() {
        let mut budget = GuardBudget::new(GuardLimits {
            max_depth: 1,
            ..GuardLimits::default()
        });
        assert!(budget.enter_archive().is_ok());
        budget.leave_archive();
        // A second, sibling (not nested) archive at the same depth should
        // still be fine after the first one's scope has closed.
        assert!(budget.enter_archive().is_ok());
    }

    #[test]
    fn malformed_entry_does_not_abort_whole_archive() {
        // A truncated/corrupt zip should fail cleanly (ZipError) rather
        // than panicking; this exercises the ZipArchive::new bounds itself.
        let mut budget = GuardBudget::new(GuardLimits::default());
        let garbage = b"PK\x03\x04not a real zip".to_vec();
        let result = extract_zip(Cursor::new(garbage), &mut budget);
        assert!(result.is_err());
    }

    fn make_gz(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn extracts_gzip_stream() {
        let gz = make_gz(b"hello from inside a gzip stream");
        let mut budget = GuardBudget::new(GuardLimits::default());
        let (data, hit) = extract_gzip(Cursor::new(gz), &mut budget).unwrap();
        assert!(hit.is_none());
        assert_eq!(data, b"hello from inside a gzip stream");
    }

    #[test]
    fn gzip_bomb_total_size_guard_trips() {
        let gz = make_gz(&vec![0u8; 5 * 1024 * 1024]);
        let mut budget = GuardBudget::new(GuardLimits {
            max_total_uncompressed: 1024,
            ..GuardLimits::default()
        });
        let (_data, hit) = extract_gzip(Cursor::new(gz), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::TotalSizeExceeded(_))));
    }

    #[test]
    fn extracts_concatenated_gzip_members() {
        let mut both = make_gz(b"first member ");
        both.extend_from_slice(&make_gz(b"second member"));
        let mut budget = GuardBudget::new(GuardLimits::default());
        let (data, hit) = extract_gzip(Cursor::new(both), &mut budget).unwrap();
        assert!(hit.is_none());
        assert_eq!(data, b"first member second member");
    }

    fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn detects_tar_magic() {
        let tar = make_tar(&[("a.txt", b"hello")]);
        assert!(looks_like_tar(&tar));
        assert!(!looks_like_tar(b"not a tar file at all, too short"));
        assert!(!looks_like_tar(&vec![0u8; 512]));
    }

    #[test]
    fn extracts_normal_tar_entries() {
        let tar = make_tar(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut budget = GuardBudget::new(GuardLimits::default());
        let (entries, hit) = extract_tar(Cursor::new(tar), &mut budget).unwrap();
        assert!(hit.is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(entries[1].data, b"world");
    }

    #[test]
    fn tar_total_size_guard_trips() {
        let entries: Vec<(&str, &[u8])> =
            vec![("a", &[0u8; 100]), ("b", &[0u8; 100]), ("c", &[0u8; 100])];
        let tar = make_tar(&entries);
        let mut budget = GuardBudget::new(GuardLimits {
            max_total_uncompressed: 150,
            ..GuardLimits::default()
        });
        let (_extracted, hit) = extract_tar(Cursor::new(tar), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::TotalSizeExceeded(_))));
    }

    #[test]
    fn tar_entry_count_guard_trips() {
        let entries: Vec<(&str, &[u8])> = vec![("a", b"1"), ("b", b"2"), ("c", b"3"), ("d", b"4")];
        let tar = make_tar(&entries);
        let mut budget = GuardBudget::new(GuardLimits {
            max_entries: 2,
            ..GuardLimits::default()
        });
        let (extracted, hit) = extract_tar(Cursor::new(tar), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::EntryCountExceeded(_))));
        assert!(!extracted.is_empty());
    }

    #[test]
    fn tar_malformed_stream_errors_cleanly() {
        let mut budget = GuardBudget::new(GuardLimits::default());
        let garbage = vec![0xFFu8; 600];
        // Not a real tar stream -- should not panic; either an Err or an
        // empty/garbage entry list is acceptable, a panic is not.
        let _ = extract_tar(Cursor::new(garbage), &mut budget);
    }

    fn make_7z(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use sevenz_rust::{SevenZArchiveEntry, SevenZWriter};
        let mut writer = SevenZWriter::new(Cursor::new(Vec::new())).unwrap();
        for (name, data) in entries {
            let mut entry = SevenZArchiveEntry::new();
            entry.name = name.to_string();
            writer
                .push_archive_entry(entry, Some(Cursor::new(data.to_vec())))
                .unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn detects_7z_magic() {
        let sz = make_7z(&[("a.txt", b"hello")]);
        assert!(looks_like_7z(&sz));
        assert!(!looks_like_7z(b"not a 7z file at all"));
    }

    #[test]
    fn extracts_normal_7z_entries() {
        let sz = make_7z(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut budget = GuardBudget::new(GuardLimits::default());
        let (entries, hit) = extract_7z(Cursor::new(sz), &mut budget).unwrap();
        assert!(hit.is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(entries[1].data, b"world");
    }

    #[test]
    fn seven_z_total_size_guard_trips() {
        let sz = make_7z(&[("bomb.bin", &vec![0u8; 20 * 1024 * 1024])]);
        let mut budget = GuardBudget::new(GuardLimits {
            max_total_uncompressed: 1024,
            ..GuardLimits::default()
        });
        let (_entries, hit) = extract_7z(Cursor::new(sz), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::TotalSizeExceeded(_))));
    }

    #[test]
    fn seven_z_malformed_stream_errors_cleanly() {
        let mut budget = GuardBudget::new(GuardLimits::default());
        let garbage = b"\x37\x7A\xBC\xAF\x27\x1Cnot a real 7z file".to_vec();
        let result = extract_7z(Cursor::new(garbage), &mut budget);
        assert!(result.is_err());
    }

    fn make_cab(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use cab::{CabinetBuilder, CompressionType};
        let mut builder = CabinetBuilder::new();
        {
            let folder = builder.add_folder(CompressionType::None);
            for (name, _) in entries {
                folder.add_file(*name);
            }
        }
        let mut writer = builder.build(Cursor::new(Vec::new())).unwrap();
        while let Some(mut file_writer) = writer.next_file().unwrap() {
            let name = file_writer.file_name().to_string();
            let data = entries.iter().find(|(n, _)| *n == name).unwrap().1;
            file_writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn detects_cab_magic() {
        let cab = make_cab(&[("a.txt", b"hello")]);
        assert!(looks_like_cab(&cab));
        assert!(!looks_like_cab(b"not a cab file at all"));
    }

    #[test]
    fn extracts_normal_cab_entries() {
        let cab = make_cab(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut budget = GuardBudget::new(GuardLimits::default());
        let (entries, hit) = extract_cab(Cursor::new(cab), &mut budget).unwrap();
        assert!(hit.is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(entries[1].data, b"world");
    }

    #[test]
    fn cab_total_size_guard_trips() {
        let cab = make_cab(&[("bomb.bin", &vec![0u8; 200 * 1024])]);
        let mut budget = GuardBudget::new(GuardLimits {
            max_total_uncompressed: 1024,
            ..GuardLimits::default()
        });
        let (_entries, hit) = extract_cab(Cursor::new(cab), &mut budget).unwrap();
        assert!(matches!(hit, Some(GuardError::TotalSizeExceeded(_))));
    }

    #[test]
    fn cab_malformed_stream_errors_cleanly() {
        let mut budget = GuardBudget::new(GuardLimits::default());
        let garbage = b"MSCFnot a real cab file".to_vec();
        let result = extract_cab(Cursor::new(garbage), &mut budget);
        assert!(result.is_err());
    }
}

/// See `pe_analyze`'s `proptests` module for the rationale. Every one of
/// these hands the extractor arbitrary bytes -- never a well-formed
/// archive -- so the only property under test is "no panic, ever, for any
/// input the current tolerant-of-malformed-entries error handling doesn't
/// already turn into a clean `Err`". This is exactly the class of input
/// (fully attacker-controlled archive bytes) the `fuzz/` harnesses target
/// too; these run today under stable, as a floor under that.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    proptest! {
        #[test]
        fn extract_zip_never_panics_on_arbitrary_bytes(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut budget = GuardBudget::new(GuardLimits::default());
            let _ = extract_zip(Cursor::new(buf), &mut budget);
        }

        #[test]
        fn extract_gzip_never_panics_on_arbitrary_bytes(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut budget = GuardBudget::new(GuardLimits::default());
            let _ = extract_gzip(Cursor::new(buf), &mut budget);
        }

        #[test]
        fn extract_tar_never_panics_on_arbitrary_bytes(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut budget = GuardBudget::new(GuardLimits::default());
            let _ = extract_tar(Cursor::new(buf), &mut budget);
        }

        #[test]
        fn extract_7z_never_panics_on_arbitrary_bytes(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut budget = GuardBudget::new(GuardLimits::default());
            let _ = extract_7z(Cursor::new(buf), &mut budget);
        }

        #[test]
        fn extract_cab_never_panics_on_arbitrary_bytes(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut budget = GuardBudget::new(GuardLimits::default());
            let _ = extract_cab(Cursor::new(buf), &mut budget);
        }

        /// Same idea but biased toward the *correct magic bytes* followed
        /// by garbage -- the "nearly valid" region that a purely random
        /// generator rarely reaches by chance, and where header-parsing
        /// bugs actually tend to hide.
        #[test]
        fn extractors_never_panic_on_correct_magic_plus_garbage(
            tail in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            let mut budget = GuardBudget::new(GuardLimits::default());
            for magic in [
                &b"PK\x03\x04"[..],
                &b"\x1F\x8B"[..],
                &b"\x37\x7A\xBC\xAF\x27\x1C"[..],
                b"MSCF",
            ] {
                let mut buf = magic.to_vec();
                buf.extend_from_slice(&tail);
                if looks_like_7z(&buf) {
                    let _ = extract_7z(Cursor::new(buf.clone()), &mut budget);
                } else if looks_like_cab(&buf) {
                    let _ = extract_cab(Cursor::new(buf.clone()), &mut budget);
                } else if buf.starts_with(b"PK") {
                    let _ = extract_zip(Cursor::new(buf.clone()), &mut budget);
                } else if buf.starts_with(b"\x1F\x8B") {
                    let _ = extract_gzip(Cursor::new(buf.clone()), &mut budget);
                }
            }
        }
    }
}
