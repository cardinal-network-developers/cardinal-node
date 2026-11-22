//! The channel between a client and this service, which only that person may
//! open (`apps.md#the-local-interface`). It carries messages, and marks where
//! each ends, so nothing in a message gives its length: on Unix a socket of
//! type `SOCK_SEQPACKET` and mode 0600, on Windows a named pipe in message
//! mode. Everything above this sends and receives whole messages and does not
//! care which.

use std::path::Path;

/// The largest message either side sends (`apps.md#the-local-interface`).
pub const MAX_MESSAGE: usize = 256 * 1024;

/// What arrived on a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// A whole message.
    Message(Vec<u8>),
    /// A message larger than [`MAX_MESSAGE`], dropped unread.
    TooLarge,
}

fn too_large() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("a message is at most {MAX_MESSAGE} bytes"),
    )
}

#[cfg(unix)]
mod imp {
    use super::{too_large, Path, Received, MAX_MESSAGE};
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::io::unix::AsyncFd;

    /// Room in the send buffer for the largest message. Linux refuses a
    /// datagram larger than the buffer (`EMSGSIZE`), and its default buffer
    /// holds about 208 KiB; the kernel caps what is asked for at twice
    /// `net.core.wmem_max`, which is 416 KiB unless lowered.
    const SEND_BUFFER: usize = 2 * MAX_MESSAGE;

    fn socket() -> io::Result<Socket> {
        let s = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;
        ready(&s)?;
        Ok(s)
    }

    fn register(s: Socket) -> io::Result<AsyncFd<Socket>> {
        // SAFETY: the socket owns its descriptor, which stays open and the
        // same for as long as the registration: it closes only when the
        // `AsyncFd` drops, or after `into_inner` gives the socket back.
        Ok(unsafe { AsyncFd::register(s) }?)
    }

    fn ready(s: &Socket) -> io::Result<()> {
        s.set_nonblocking(true)?;
        // Best effort: where it cannot be raised, a large message fails to
        // send and says so.
        let _ = s.set_send_buffer_size(SEND_BUFFER);
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const NO_SIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const NO_SIGNAL: libc::c_int = 0;

    /// The next message, from a socket that has one waiting.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn next(s: &Socket) -> io::Result<Option<Received>> {
        // Linux tells a packet's whole length without taking it, so nothing
        // larger than what arrived is allocated.
        let len = s.recv_with_flags(&mut [], libc::MSG_PEEK | libc::MSG_TRUNC)?;
        if len > MAX_MESSAGE {
            // Taking it with a short buffer drops the rest.
            s.recv(&mut [std::mem::MaybeUninit::uninit(); 1])?;
            return Ok(Some(Received::TooLarge));
        }
        let mut buf = Vec::with_capacity(len.max(1));
        let got = s.recv(buf.spare_capacity_mut())?;
        if got == 0 {
            // The end, or an empty message, which no record is.
            return Ok(None);
        }
        // SAFETY: `recv` initialised the first `got` bytes.
        unsafe { buf.set_len(got) };
        Ok(Some(Received::Message(buf)))
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn next(s: &Socket) -> io::Result<Option<Received>> {
        let mut buf = Vec::with_capacity(MAX_MESSAGE + 1);
        let got = s.recv(buf.spare_capacity_mut())?;
        if got == 0 {
            return Ok(None);
        }
        if got > MAX_MESSAGE {
            return Ok(Some(Received::TooLarge));
        }
        // SAFETY: `recv` initialised the first `got` bytes.
        unsafe { buf.set_len(got) };
        buf.shrink_to_fit();
        Ok(Some(Received::Message(buf)))
    }

    /// The receiving half of a connection.
    pub struct Reader(Arc<AsyncFd<Socket>>);
    /// The sending half of a connection.
    pub struct Writer(Arc<AsyncFd<Socket>>);

    impl Reader {
        /// The next message, or `None` once the other side has gone.
        pub async fn recv(&mut self) -> io::Result<Option<Received>> {
            loop {
                let mut guard = self.0.readable().await?;
                if let Ok(r) = guard.try_io(|s| next(s.get_ref())) {
                    return r;
                }
            }
        }
    }

    impl Writer {
        /// Sends one whole message.
        pub async fn send(&mut self, msg: &[u8]) -> io::Result<()> {
            if msg.len() > MAX_MESSAGE {
                return Err(too_large());
            }
            loop {
                let mut guard = self.0.writable().await?;
                match guard.try_io(|s| s.get_ref().send_with_flags(msg, NO_SIGNAL)) {
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => continue,
                }
            }
        }
    }

    fn halves(s: Socket) -> io::Result<(Reader, Writer)> {
        let fd = Arc::new(register(s)?);
        Ok((Reader(fd.clone()), Writer(fd)))
    }

    pub async fn connect(path: &Path) -> io::Result<(Reader, Writer)> {
        let s = socket()?;
        let addr = SockAddr::unix(path)?;
        match s.connect(&addr) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
                let fd = register(s)?;
                fd.writable().await?.retain_ready();
                if let Some(e) = fd.get_ref().take_error()? {
                    return Err(e);
                }
                let s = fd.into_inner();
                return halves(s);
            }
            Err(e) => return Err(e),
        }
        halves(s)
    }

    /// Whether a service answers on `path`.
    pub fn answers(path: &Path) -> bool {
        let Ok(s) = Socket::new(Domain::UNIX, Type::SEQPACKET, None) else {
            return false;
        };
        SockAddr::unix(path).is_ok_and(|a| s.connect(&a).is_ok())
    }

    /// The process id of a connected socket's peer.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn peer_pid(s: &Socket) -> Option<u32> {
        use std::os::fd::AsRawFd;
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for the call, which writes at
        // most `len` bytes into `cred`.
        let r = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        (r == 0 && cred.pid > 0).then_some(cred.pid as u32)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn peer_pid(_: &Socket) -> Option<u32> {
        None
    }

    pub struct Listener(AsyncFd<Socket>);

    impl Listener {
        pub fn bind(path: &Path) -> anyhow::Result<Listener> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            if path.exists() {
                if answers(path) {
                    anyhow::bail!(
                        "a cardinal daemon is already running (socket {})",
                        path.display()
                    );
                }
                std::fs::remove_file(path)?;
            }
            let s = socket()?;
            s.bind(&SockAddr::unix(path)?)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            s.listen(16)?;
            Ok(Listener(register(s)?))
        }

        pub async fn accept(&mut self) -> io::Result<(Reader, Writer)> {
            let (r, w, _) = self.accept_peer().await?;
            Ok((r, w))
        }

        /// [`accept`](Self::accept), and the process id of the peer where
        /// the platform tells it (`SO_PEERCRED`).
        pub async fn accept_peer(&mut self) -> io::Result<(Reader, Writer, Option<u32>)> {
            loop {
                let mut guard = self.0.readable().await?;
                if let Ok(r) = guard.try_io(|s| s.get_ref().accept()) {
                    let (s, _) = r?;
                    ready(&s)?;
                    let pid = peer_pid(&s);
                    let (r, w) = halves(s)?;
                    return Ok((r, w, pid));
                }
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    //! A named pipe in message mode. Tokio's pipes read through a buffer of
    //! their own that loses where a message ends, so the pipe is driven here
    //! with overlapped I/O: each connection has a thread that reads whole
    //! messages and a thread that writes them, so that both directions run
    //! at once, as a watch or a call's media needs.

    use super::{too_large, Path, Received, MAX_MESSAGE};
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_MORE_DATA,
        ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, SetNamedPipeHandleState, PIPE_READMODE_MESSAGE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::CreateEventW;
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    /// What the pipe holds for a reader that is slower than its writer.
    const BUFFER: u32 = 64 * 1024;

    /// A pipe handle, closed when the last of its users goes. A server's is
    /// closed, not disconnected: disconnecting drops what the client has not
    /// read yet, such as the reply to `stop`.
    struct Pipe(HANDLE);

    // SAFETY: a handle may be used from any thread, and overlapped I/O on
    // one handle from two threads at once is what it is for.
    unsafe impl Send for Pipe {}
    unsafe impl Sync for Pipe {}

    impl Drop for Pipe {
        fn drop(&mut self) {
            // SAFETY: the handle is ours, and nothing uses it after this.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// An event for one overlapped operation at a time.
    struct Event(HANDLE);

    // SAFETY: as for `Pipe`; each event is used by one thread.
    unsafe impl Send for Event {}

    impl Event {
        fn new() -> io::Result<Event> {
            // SAFETY: plain call; a manual-reset event, not signalled.
            let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Event(h))
        }

        fn overlapped(&self) -> OVERLAPPED {
            // SAFETY: all zeros is a valid OVERLAPPED.
            let mut o: OVERLAPPED = unsafe { std::mem::zeroed() };
            o.hEvent = self.0;
            o
        }
    }

    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: the event is ours.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Waits for the overlapped operation on `o` that returned `started`:
    /// the bytes it moved and whether its message goes on, or the error with
    /// which it ended.
    fn finish(pipe: &Pipe, o: &mut OVERLAPPED, started: i32) -> Result<(u32, bool), u32> {
        if started == 0 {
            // SAFETY: plain call.
            let e = unsafe { GetLastError() };
            if e != ERROR_IO_PENDING && e != ERROR_MORE_DATA {
                return Err(e);
            }
        }
        let mut n = 0u32;
        // SAFETY: `o` is the operation's, and outlives the wait.
        if unsafe { GetOverlappedResult(pipe.0, o, &mut n, 1) } != 0 {
            return Ok((n, false));
        }
        // SAFETY: plain call.
        match unsafe { GetLastError() } {
            ERROR_MORE_DATA => Ok((n, true)),
            e => Err(e),
        }
    }

    /// Reads one whole message: `None` once the other side has gone, or the
    /// reader with it.
    fn read_message(pipe: &Pipe, event: &Event) -> io::Result<Option<Received>> {
        let mut chunk = vec![0u8; BUFFER as usize];
        let mut message = Vec::new();
        let mut too_big = false;
        loop {
            let mut o = event.overlapped();
            // SAFETY: the buffer and `o` outlive the operation, which
            // `finish` waits for.
            let started = unsafe {
                ReadFile(
                    pipe.0,
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    std::ptr::null_mut(),
                    &mut o,
                )
            };
            match finish(pipe, &mut o, started) {
                Ok((n, more)) => {
                    let n = n as usize;
                    if message.len() + n > MAX_MESSAGE {
                        too_big = true;
                        message = Vec::new();
                    } else if !too_big {
                        message.extend_from_slice(&chunk[..n]);
                    }
                    if !more {
                        return Ok(Some(if too_big {
                            Received::TooLarge
                        } else {
                            Received::Message(message)
                        }));
                    }
                }
                Err(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_OPERATION_ABORTED) => {
                    return Ok(None)
                }
                Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }

    fn write_message(pipe: &Pipe, event: &Event, msg: &[u8]) -> io::Result<()> {
        let mut o = event.overlapped();
        // SAFETY: the message and `o` outlive the operation.
        let started = unsafe {
            WriteFile(
                pipe.0,
                msg.as_ptr(),
                msg.len() as u32,
                std::ptr::null_mut(),
                &mut o,
            )
        };
        match finish(pipe, &mut o, started) {
            Ok((n, _)) if n as usize == msg.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "part of a message",
            )),
            Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// The receiving half of a connection.
    pub struct Reader {
        rx: mpsc::Receiver<io::Result<Option<Received>>>,
        pipe: Arc<Pipe>,
    }

    /// The sending half of a connection.
    pub struct Writer {
        tx: std::sync::mpsc::Sender<(Vec<u8>, oneshot::Sender<io::Result<()>>)>,
    }

    impl Reader {
        /// The next message, or `None` once the other side has gone.
        pub async fn recv(&mut self) -> io::Result<Option<Received>> {
            match self.rx.recv().await {
                Some(r) => r,
                None => Ok(None),
            }
        }
    }

    impl Drop for Reader {
        fn drop(&mut self) {
            // Wake the reading thread, so that it lets the pipe go.
            // SAFETY: the handle is open while `self.pipe` holds it.
            unsafe { CancelIoEx(self.pipe.0, std::ptr::null()) };
        }
    }

    impl Writer {
        /// Sends one whole message.
        pub async fn send(&mut self, msg: &[u8]) -> io::Result<()> {
            if msg.len() > MAX_MESSAGE {
                return Err(too_large());
            }
            let (done, wait) = oneshot::channel();
            let gone = || io::Error::new(io::ErrorKind::BrokenPipe, "the pipe closed");
            self.tx.send((msg.to_vec(), done)).map_err(|_| gone())?;
            wait.await.map_err(|_| gone())?
        }
    }

    fn halves(pipe: Pipe) -> io::Result<(Reader, Writer)> {
        let pipe = Arc::new(pipe);
        let (read_event, write_event) = (Event::new()?, Event::new()?);
        let (rtx, rx) = mpsc::channel(4);
        let p = pipe.clone();
        std::thread::spawn(move || loop {
            let r = read_message(&p, &read_event);
            let end = !matches!(r, Ok(Some(_)));
            if rtx.blocking_send(r).is_err() || end {
                return;
            }
        });
        let (tx, wrx) = std::sync::mpsc::channel::<(Vec<u8>, oneshot::Sender<io::Result<()>>)>();
        let p = pipe.clone();
        std::thread::spawn(move || {
            while let Ok((msg, done)) = wrx.recv() {
                let r = write_message(&p, &write_event, &msg);
                let failed = r.is_err();
                let _ = done.send(r);
                if failed {
                    return;
                }
            }
        });
        Ok((Reader { rx, pipe }, Writer { tx }))
    }

    fn wide(path: &Path) -> Vec<u16> {
        OsStr::new(path).encode_wide().chain(Some(0)).collect()
    }

    fn open(path: &Path) -> io::Result<Pipe> {
        let name = wide(path);
        // SAFETY: `name` is a NUL-terminated wide string.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let pipe = Pipe(h);
        let mode = PIPE_READMODE_MESSAGE;
        // SAFETY: `h` is a pipe handle; `mode` outlives the call.
        if unsafe { SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pipe)
    }

    pub async fn connect(path: &Path) -> io::Result<(Reader, Writer)> {
        let mut tries = 0;
        loop {
            match open(path) {
                Ok(pipe) => return halves(pipe),
                // The next instance is a moment away.
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 20 => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Whether a service answers on `path`.
    pub fn answers(path: &Path) -> bool {
        match open(path) {
            Ok(_) => true,
            Err(e) => e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32),
        }
    }

    fn instance(path: &Path, first: bool) -> io::Result<Pipe> {
        let name = wide(path);
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // The default security lets only this user and administrators write,
        // and anyone read, which here only ties up an instance. It does not
        // stop another account from taking the name while no daemon runs
        // (DEVIATIONS.md, Clients).
        // SAFETY: `name` is a NUL-terminated wide string.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER,
                BUFFER,
                0,
                std::ptr::null(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Pipe(h))
    }

    /// Waits on a thread of its own for a client to open `pipe`.
    fn wait_for_client(pipe: Pipe) -> io::Result<Pipe> {
        let event = Event::new()?;
        let mut o = event.overlapped();
        // SAFETY: `o` outlives the operation, which `finish` waits for.
        let started = unsafe { ConnectNamedPipe(pipe.0, &mut o) };
        if started == 0 && unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
            return Ok(pipe);
        }
        match finish(&pipe, &mut o, started) {
            Ok(_) => Ok(pipe),
            Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// A pipe has an instance per client, so one waits for the next.
    pub struct Listener {
        path: std::path::PathBuf,
        next: Option<Pipe>,
    }

    impl Listener {
        pub fn bind(path: &Path) -> anyhow::Result<Listener> {
            let next = instance(path, true)
                .map_err(|e| anyhow::anyhow!("a cardinal daemon may already be running: {e}"))?;
            Ok(Listener {
                path: path.to_owned(),
                next: Some(next),
            })
        }

        pub async fn accept(&mut self) -> io::Result<(Reader, Writer)> {
            let pipe = match self.next.take() {
                Some(p) => p,
                None => instance(&self.path, false)?,
            };
            let (tx, rx) = oneshot::channel();
            // Not a blocking task of the runtime's: one that waits for a
            // client would keep the service from stopping.
            std::thread::spawn(move || {
                let _ = tx.send(wait_for_client(pipe));
            });
            let pipe = rx
                .await
                .map_err(|_| io::Error::other("the pipe's waiting thread ended"))??;
            self.next = Some(instance(&self.path, false)?);
            halves(pipe)
        }
    }
}

pub use imp::{answers, connect, Listener, Reader, Writer};
