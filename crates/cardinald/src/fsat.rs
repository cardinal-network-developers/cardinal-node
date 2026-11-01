//! Reading and writing a file at an offset, on any platform.

use std::fs::File;
use std::io;

#[cfg(unix)]
pub use std::os::unix::fs::FileExt;

/// `std::os::unix::fs::FileExt`, for Windows, whose own version moves the
/// file's cursor. Nothing here relies on the cursor.
#[cfg(windows)]
pub trait FileExt {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize>;
    fn write_at(&self, buf: &[u8], off: u64) -> io::Result<usize>;

    fn read_exact_at(&self, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, off)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => {
                    buf = &mut buf[n..];
                    off += n as u64;
                }
            }
        }
        Ok(())
    }

    fn write_all_at(&self, mut buf: &[u8], mut off: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write_at(buf, off)? {
                0 => return Err(io::ErrorKind::WriteZero.into()),
                n => {
                    buf = &buf[n..];
                    off += n as u64;
                }
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
impl FileExt for File {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        std::os::windows::fs::FileExt::seek_read(self, buf, off)
    }

    fn write_at(&self, buf: &[u8], off: u64) -> io::Result<usize> {
        std::os::windows::fs::FileExt::seek_write(self, buf, off)
    }
}

/// Makes the compiler see `File` used on Unix too.
#[cfg(unix)]
const _: Option<(File, io::Error)> = None;
