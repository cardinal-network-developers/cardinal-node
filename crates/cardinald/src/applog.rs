//! An append-only file of records: `u32` little-endian length, then the
//! bytes. Used for identity entries and sealed space entries, which are
//! immutable objects. A torn record at the end (a crash mid-append) is cut
//! off when the file is opened.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

/// Where a record lives in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loc {
    /// Offset of the record's bytes.
    pub offset: u64,
    /// Their length.
    pub len: u32,
}

/// An append-only record file.
pub struct AppendLog {
    file: File,
    end: u64,
}

impl AppendLog {
    /// Opens (or creates) the file and returns every record in it.
    pub fn open(path: &Path) -> std::io::Result<(AppendLog, Vec<(Loc, Vec<u8>)>)> {
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
            file.set_len(pos as u64)?;
        }
        Ok((
            AppendLog {
                file,
                end: pos as u64,
            },
            out,
        ))
    }

    /// Appends a record and makes it durable.
    pub fn append(&mut self, bytes: &[u8]) -> std::io::Result<Loc> {
        let mut buf = Vec::with_capacity(bytes.len() + 4);
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
        self.file.write_all(&buf)?;
        self.file.sync_data()?;
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
            self.file.write_all(&buf)?;
            self.file.sync_data()?;
        }
        self.end = at;
        Ok(locs)
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
}
