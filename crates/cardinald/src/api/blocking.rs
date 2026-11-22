//! A client of the local interface that waits for each answer: for tests
//! and tools that have no runtime of their own. It speaks the tables by
//! name, as [`super::encode_request`] and [`super::decode_reply`] do.

use std::io;
use std::path::Path;
use std::time::Duration;

use serde_json::Value as Json;
use socket2::{Domain, SockAddr, Socket, Type};

use super::{decode_reply, encode_request, Request};
use crate::transport::MAX_MESSAGE;

/// One connection to a service.
pub struct Client {
    s: Socket,
    /// Room for the largest message, and one byte more.
    buf: Vec<u8>,
    /// The last request sent, whose reply comes next.
    last: Option<&'static Request>,
}

impl Client {
    pub fn connect(path: &Path) -> io::Result<Client> {
        let s = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;
        let _ = s.set_send_buffer_size(2 * MAX_MESSAGE);
        s.connect(&SockAddr::unix(path)?)?;
        Ok(Client {
            s,
            buf: Vec::with_capacity(MAX_MESSAGE + 1),
            last: None,
        })
    }

    /// How long a receive waits before it gives up; `None` for ever.
    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.s.set_read_timeout(t)
    }

    /// Sends a message as it is.
    pub fn send_raw(&mut self, msg: &[u8]) -> io::Result<()> {
        self.s.send(msg).map(|_| ())
    }

    /// The next message as it is: `None` once the service has gone.
    pub fn recv_raw(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.buf.clear();
        let n = self.s.recv(self.buf.spare_capacity_mut())?;
        if n == 0 {
            return Ok(None);
        }
        // SAFETY: `recv` initialised the first `n` bytes.
        unsafe { self.buf.set_len(n) };
        Ok(Some(self.buf.clone()))
    }

    /// Sends a request, named in `cmd` with its arguments by name.
    pub fn send(&mut self, req: &Json) -> anyhow::Result<()> {
        let (spec, msg) = encode_request(req)?;
        self.send_raw(&msg)?;
        self.last = Some(spec);
        Ok(())
    }

    /// The reply to the request sent last, by name, with `ok`.
    pub fn reply(&mut self) -> anyhow::Result<Json> {
        let spec = self
            .last
            .ok_or_else(|| anyhow::anyhow!("no request was sent"))?;
        let msg = self
            .recv_raw()?
            .ok_or_else(|| anyhow::anyhow!("the service closed the connection"))?;
        decode_reply(spec, &msg)
    }

    /// Sends a request and waits for its reply.
    pub fn ask(&mut self, req: &Json) -> anyhow::Result<Json> {
        self.send(req)?;
        self.reply()
    }

    /// The next event of a `watch`: `{"event": "changed", "seq": n}`.
    pub fn event(&mut self) -> anyhow::Result<Option<Json>> {
        match self.recv_raw()? {
            Some(msg) => super::decode_event(&msg),
            None => Ok(None),
        }
    }

    /// The next frame of a `call-media` connection, by name:
    /// `{"audio": hex, "from": hex}` or `{"frame": hex, "format": hex}`.
    pub fn frame(&mut self) -> anyhow::Result<Option<Json>> {
        match self.recv_raw()? {
            Some(msg) => super::decode_frame(&msg),
            None => Ok(None),
        }
    }

    /// Sends a frame on a `call-media` connection, named as [`Client::frame`]
    /// gives them.
    pub fn send_frame(&mut self, frame: &Json) -> anyhow::Result<()> {
        let msg = super::frame_message(frame)?;
        self.send_raw(&msg)?;
        Ok(())
    }
}
