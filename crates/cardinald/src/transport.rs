//! The channel between a client and this service, which only that person may
//! open: a socket of mode 0600 on Unix, a named pipe on Windows. Everything
//! above this speaks lines of JSON and does not care which.

use std::path::Path;

#[cfg(unix)]
mod imp {
    use super::Path;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::{UnixListener, UnixStream};

    pub type Reader = OwnedReadHalf;
    pub type Writer = OwnedWriteHalf;

    pub async fn connect(path: &Path) -> std::io::Result<(Reader, Writer)> {
        Ok(UnixStream::connect(path).await?.into_split())
    }

    pub struct Listener(UnixListener);

    impl Listener {
        pub fn bind(path: &Path) -> anyhow::Result<Listener> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            if path.exists() {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    anyhow::bail!(
                        "a cardinal daemon is already running (socket {})",
                        path.display()
                    );
                }
                std::fs::remove_file(path)?;
            }
            let listener = UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Listener(listener))
        }

        pub async fn accept(&mut self) -> std::io::Result<(Reader, Writer)> {
            Ok(self.0.accept().await?.0.into_split())
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::Path;
    use tokio::io::{split, ReadHalf, WriteHalf};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    /// Either end of a pipe.
    pub enum End {
        Server(NamedPipeServer),
        Client(NamedPipeClient),
    }

    macro_rules! either {
        ($self:ident, $e:ident => $do:expr) => {
            match $self.get_mut() {
                End::Server($e) => $do,
                End::Client($e) => $do,
            }
        };
    }

    impl tokio::io::AsyncRead for End {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            either!(self, e => std::pin::Pin::new(e).poll_read(cx, buf))
        }
    }

    impl tokio::io::AsyncWrite for End {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            either!(self, e => std::pin::Pin::new(e).poll_write(cx, buf))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            either!(self, e => std::pin::Pin::new(e).poll_flush(cx))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            either!(self, e => std::pin::Pin::new(e).poll_shutdown(cx))
        }
    }

    pub type Reader = ReadHalf<End>;
    pub type Writer = WriteHalf<End>;

    pub async fn connect(path: &Path) -> std::io::Result<(Reader, Writer)> {
        /// `ERROR_PIPE_BUSY`: the next instance is a moment away.
        const BUSY: i32 = 231;
        let mut tries = 0;
        loop {
            match ClientOptions::new().open(path.as_os_str()) {
                Ok(pipe) => return Ok(split(End::Client(pipe))),
                Err(e) if e.raw_os_error() == Some(BUSY) && tries < 20 => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// A pipe has an instance per client, so one waits for the next.
    pub struct Listener {
        path: std::path::PathBuf,
        next: NamedPipeServer,
    }

    fn instance(path: &Path, first: bool) -> std::io::Result<NamedPipeServer> {
        // The default security lets only this user and administrators write,
        // and anyone read, which here only ties up an instance. It does not
        // stop another account from taking the name while no daemon runs
        // (DEVIATIONS.md, Clients).
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create(path.as_os_str())
    }

    impl Listener {
        pub fn bind(path: &Path) -> anyhow::Result<Listener> {
            let next = instance(path, true)
                .map_err(|e| anyhow::anyhow!("a cardinal daemon may already be running: {e}"))?;
            Ok(Listener {
                path: path.to_owned(),
                next,
            })
        }

        pub async fn accept(&mut self) -> std::io::Result<(Reader, Writer)> {
            self.next.connect().await?;
            let again = instance(&self.path, false)?;
            let server = std::mem::replace(&mut self.next, again);
            Ok(split(End::Server(server)))
        }
    }
}

pub use imp::{connect, Listener, Reader, Writer};
