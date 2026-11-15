//! An append-only file of records: `u32` little-endian length, then the
//! bytes. Used for identity entries and sealed space entries, which are
//! immutable objects. A torn record at the end (a crash mid-append) is cut
//! off when the file is opened. An append that fails part way is cut off
//! again at once, and nothing is appended behind what could not be cut.

use crate::fsat::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Where a record lives in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loc {
    /// Offset of the record's bytes.
    pub offset: u64,
    /// Their length.
    pub len: u32,
}

/// Records read when opening: where each is, and its bytes.
pub type Records = Vec<(Loc, Vec<u8>)>;

/// An append-only record file.
pub struct AppendLog {
    file: File,
    path: PathBuf,
    end: u64,
    /// Something is at the end that is no record and could not be cut:
    /// nothing more is appended, since its place could not be told.
    broken: bool,
}

impl AppendLog {
    /// Opens (or creates) the file and returns every record in it.
    pub fn open(path: &Path) -> std::io::Result<(AppendLog, Records)> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let mut all = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut all)?;
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 4 <= all.len() {
            let len = u32::from_le_bytes(all[pos..pos + 4].try_into().expect("4")) as usize;
            if pos + 4 + len > all.len() {
                break;
            }
            out.push((
                Loc {
                    offset: (pos + 4) as u64,
                    len: len as u32,
                },
                all[pos + 4..pos + 4 + len].to_vec(),
            ));
            pos += 4 + len;
        }
        if pos != all.len() {
            tracing::warn!(
                path = %path.display(),
                "cutting a torn record at the end of the log"
            );
            // On a handle of its own: Windows does not let one that only
            // appends change a file's length.
            OpenOptions::new()
                .write(true)
                .open(path)?
                .set_len(pos as u64)?;
        }
        Ok((
            AppendLog {
                file,
                path: path.to_path_buf(),
                end: pos as u64,
                broken: false,
            },
            out,
        ))
    }

    /// Appends a record and makes it durable.
    pub fn append(&mut self, bytes: &[u8]) -> std::io::Result<Loc> {
        let mut buf = Vec::with_capacity(bytes.len() + 4);
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
        self.write(&buf)?;
        let loc = Loc {
            offset: self.end + 4,
            len: bytes.len() as u32,
        };
        self.end += buf.len() as u64;
        Ok(loc)
    }

    /// Appends several records with one sync.
    pub fn append_many(&mut self, records: &[&[u8]]) -> std::io::Result<Vec<Loc>> {
        let mut buf = Vec::new();
        let mut locs = Vec::new();
        let mut at = self.end;
        for r in records {
            buf.extend_from_slice(&(r.len() as u32).to_le_bytes());
            buf.extend_from_slice(r);
            locs.push(Loc {
                offset: at + 4,
                len: r.len() as u32,
            });
            at += 4 + r.len() as u64;
        }
        if !buf.is_empty() {
            self.write(&buf)?;
        }
        self.end = at;
        Ok(locs)
    }

    /// Writes whole records at the end and makes them durable, or leaves
    /// the file ending where it did. Records are found by where the log
    /// ended when they were written, so nothing may lie between: bytes a
    /// failed write left there are cut first, and a write that fails is
    /// cut back. If that cannot be done the log takes nothing more.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if !self.broken && self.file.metadata()?.len() != self.end {
            self.cut();
        }
        if self.broken {
            return Err(std::io::Error::other(format!(
                "{} ends in something that is not a record and could not be removed",
                self.path.display()
            )));
        }
        let written = self.file.write_all(buf);
        let written = written.and_then(|()| self.file.sync_data());
        if written.is_err() {
            self.cut();
        }
        written
    }

    /// Cuts the file back to its last whole record.
    fn cut(&mut self) {
        tracing::warn!(path = %self.path.display(), "cutting what a failed write left in the log");
        // On a handle of its own, as when opening.
        let cut = OpenOptions::new().write(true).open(&self.path);
        let cut = cut.and_then(|f| f.set_len(self.end).and_then(|()| f.sync_data()));
        let len = self.file.metadata().map(|m| m.len());
        self.broken = cut.is_err() || len.ok() != Some(self.end);
    }

    /// Makes the log refuse what is appended from now on, as it does once
    /// it cannot cut what a failed write left.
    #[cfg(test)]
    pub fn break_for_test(&mut self) {
        self.broken = true;
    }

    /// Reads a record.
    pub fn read(&self, loc: Loc) -> std::io::Result<Vec<u8>> {
        let mut b = vec![0u8; loc.len as usize];
        self.file.read_exact_at(&mut b, loc.offset)?;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_torn_tail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.log");
        {
            let (mut l, recs) = AppendLog::open(&p).unwrap();
            assert!(recs.is_empty());
            let a = l.append(b"hello").unwrap();
            let bs = l.append_many(&[b"a", b"bc"]).unwrap();
            assert_eq!(l.read(a).unwrap(), b"hello");
            assert_eq!(l.read(bs[1]).unwrap(), b"bc");
        }
        // a torn record
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[9, 0, 0, 0, 1]).unwrap();
        }
        let (mut l, recs) = AppendLog::open(&p).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[2].1, b"bc");
        let x = l.append(b"z").unwrap();
        assert_eq!(l.read(x).unwrap(), b"z");
        let (_, recs) = AppendLog::open(&p).unwrap();
        assert_eq!(recs.len(), 4);
    }

    /// D2. An append that failed part way leaves part of a record at the
    /// end. The next one must not land behind it: its place would be
    /// reckoned from where the log ended before, and on opening again
    /// everything from the torn bytes on would be cut.
    #[test]
    fn what_a_failed_append_left_is_cut_before_the_next() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.log");
        let (mut l, _) = AppendLog::open(&p).unwrap();
        let a = l.append(b"first").unwrap();
        // half a record, as a write that failed part way leaves it
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[9, 0, 0, 0, b'h', b'a']).unwrap();
        }
        let b = l.append(b"second").unwrap();
        let cs = l.append_many(&[b"third", b"fourth"]).unwrap();
        assert_eq!(l.read(a).unwrap(), b"first");
        assert_eq!(l.read(b).unwrap(), b"second");
        assert_eq!(l.read(cs[1]).unwrap(), b"fourth");
        let (_, recs) = AppendLog::open(&p).unwrap();
        let all: Vec<&[u8]> = recs.iter().map(|(_, r)| r.as_slice()).collect();
        assert_eq!(all, [&b"first"[..], b"second", b"third", b"fourth"]);
    }
}
