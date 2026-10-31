//! A device as a host for its own identity (`hosts.md`), and restoring
//! from one: "lost everything: the 24 words and the always-on device's
//! address" (`hosts.md#restore`).
//!
//! `cardinal host` makes a device of this person's a host: it keeps
//! everything, records a grant in the account space, and accepts restore
//! sessions. Those come from devices it has never seen, so until one
//! proves it holds the root key it may do nothing else ([`is_unproven`]).
//!
//! A restoring device then joins as a paired device does: it collects the
//! identity log, adds itself with the root key, and reconnects as one of
//! this person's devices, and ordinary sync brings every space.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{verify, RecoveryPhrase, SigningKey};
use cardinal_encoding::{Record, Value};
use cardinal_identity::Power;
use cardinal_link::{
    Admission, CarrierKind, LinkError, Priority, Role, Service, Session, Stream, Target,
};
use cardinal_space::account;
use cardinal_space::grant::{Endpoint, Grant, STORAGE};
use cardinal_space::SpaceOp;
use cardinal_sync::identity_log_label;
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::daemon::{Daemon, PairState};
use crate::net::{self, Access};

/// How long a session from an unknown device has to prove itself.
pub const PROVE_WITHIN: Duration = Duration::from_secs(30);

const PROVE_CONTEXT: &[u8] = b"cardinal restore";
const OP_ERROR: u64 = 0;
const OP_PROVE: u64 = 5;
const NOT_PERMITTED: u64 = 1;
const UNKNOWN: u64 = 3;

/// Characters of a sheet key: Crockford's base 32, which has no letters
/// that read like others, in lower case.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const CHECK_BYTES: usize = 3;

/// A static key as a person copies it from a recovery sheet, with a check
/// so that a slip is caught at once, not as a host that seems to be down.
pub fn sheet_key(key: &[u8; 32]) -> String {
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&blake3::hash(key).as_bytes()[..CHECK_BYTES]);
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0);
    for b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if !out.is_empty() && out.replace('-', "").len() % 4 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

/// Reads a sheet key, however it was typed.
pub fn read_sheet_key(s: &str) -> Option<[u8; 32]> {
    let (mut acc, mut bits) = (0u32, 0);
    let mut bytes = Vec::new();
    for c in s.chars().filter(|c| !matches!(c, '-' | ' ')) {
        let c = match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        };
        let v = ALPHABET.iter().position(|a| *a as char == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bytes.len() != 32 + CHECK_BYTES {
        return None;
    }
    let key: [u8; 32] = bytes[..32].try_into().ok()?;
    (blake3::hash(&key).as_bytes()[..CHECK_BYTES] == bytes[32..]).then_some(key)
}

/// Whether a session came from a device this one does not know, and has
/// not proved anything: it may do nothing but `prove`.
pub fn is_unproven(d: &Daemon, s: &Session) -> bool {
    s.role() == Role::Responder
        && s.admission() == Admission::Public
        && !d.is_proven(&s.peer_static())
}

/// Makes this device a host for its own identity, at `addresses`.
pub fn enable(d: &Arc<Daemon>, addresses: &[String]) -> anyhow::Result<Json> {
    if addresses.is_empty() {
        anyhow::bail!(
            "give an address other devices can reach this one at: \
             `cardinal host --address <host:port>`"
        );
    }
    let endpoints = addresses
        .iter()
        .map(|a| {
            Endpoint::parse(a).ok_or_else(|| {
                anyhow::anyhow!("{a} is not an address; it looks like 192.168.1.20:7171")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let listening = d.endpoint.tcp_addr().map_or(0, |a| a.port());
    let mut warnings: Vec<String> = endpoints
        .iter()
        .filter_map(|e| address_warning(e, listening))
        .collect();
    warnings.extend(logout_warning());
    let (space, mut ops) = own_nodes(d, true)?;
    let identity = own_identity(d)?;
    let grant = Grant {
        host: identity,
        served: identity,
        services: vec![STORAGE],
        storage_bytes: 0,
        retention_days: 0,
        endpoints,
        link_key: d.keys.link.public_key().clone(),
    }
    .sign(&d.keys.signing);
    ops.push(account::create_host(&grant));
    d.write_and_push(&space, ops)?;
    {
        let mut c = d.config();
        c.host = true;
        c.retention = "full".into();
    }
    d.save_config()?;
    d.endpoint.set_allow_public(true);
    d.housekeeping();
    let mut out = sheet(d)?;
    out["warnings"] = json!(warnings);
    Ok(out)
}

/// Why a restore would not reach this device at `e`, as far as this device
/// can tell. Host names and addresses that belong to a router in front of
/// it cannot be checked from here.
fn address_warning(e: &Endpoint, listening: u16) -> Option<String> {
    let at = e.socket_addr()?;
    let here = std::net::UdpSocket::bind((at.ip(), 0)).is_ok();
    if here && e.port != listening {
        return Some(format!(
            "this device listens on port {listening}, so {e} will not reach it."
        ));
    }
    let private = matches!(at.ip(), IpAddr::V4(ip) if ip.is_private());
    (!here && private).then(|| {
        format!("{e} is not an address of this device, so a restore will not reach it there.")
    })
}

/// Whether a daemon in this control group stops at logout: a user service
/// lasts only as long as its user manager, unless the user lingers.
fn stops_at_logout(cgroup: &str, linger: &str) -> bool {
    cgroup.contains("/user@") && linger.trim() == "no"
}

fn logout_warning() -> Option<String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() }.to_string();
    let linger = std::process::Command::new("loginctl")
        .args(["show-user", &uid, "--property=Linger", "--value"])
        .output()
        .ok()?;
    let linger = String::from_utf8_lossy(&linger.stdout);
    stops_at_logout(&cgroup, &linger).then(|| {
        let user = std::env::var("USER").unwrap_or(uid);
        format!(
            "this device stops when you log out of it, so it would not be there for a restore. \
             Keep it running with: sudo loginctl enable-linger {user}"
        )
    })
}

/// Stops being a host: this device keeps what it has, and no longer offers
/// to restore anyone.
pub fn disable(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    let (space, ops) = own_nodes(d, false)?;
    d.write_and_push(&space, ops)?;
    d.config().host = false;
    d.save_config()?;
    d.endpoint.set_allow_public(false);
    sheet(d)
}

fn own_identity(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    d.core()
        .identity
        .as_ref()
        .map(|i| i.id())
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))
}

/// The account space, and ops that mark this device as a host or not and
/// take back any grant it made before.
fn own_nodes(d: &Daemon, host: bool) -> anyhow::Result<([u8; 32], Vec<SpaceOp>)> {
    let core = d.core();
    let acc = core
        .account()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet; try again shortly"))?;
    let st = acc
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the account space is not open yet"))?
        .state();
    let me = d.keys.key();
    let mut ops = Vec::new();
    for h in account::hosts(st) {
        if Grant::open(&h.grant).is_some_and(|(_, signer)| signer == me) {
            ops.push(SpaceOp::delete(h.node));
        }
    }
    if let Some(n) = account::devices(st).into_iter().find(|n| n.key == me) {
        ops.push(account::set_field(n.node, 3, host));
        ops.push(account::set_field(n.node, 4, host));
    }
    Ok((acc.id, ops))
}

/// What belongs on the recovery sheet: this identity's hosts.
pub fn sheet(d: &Daemon) -> anyhow::Result<Json> {
    let core = d.core();
    let ident = core
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    let st = ident.state();
    let names = core.device_names();
    let hosts = core
        .account()
        .and_then(|a| a.space.as_ref())
        .map(|sp| account::hosts(sp.state()))
        .unwrap_or_default();
    let hosts: Vec<Json> = hosts
        .iter()
        .filter_map(|h| Grant::open(&h.grant))
        .filter(|(g, signer)| {
            g.services.contains(&STORAGE) && g.served == ident.id() && st.power(signer).is_some()
        })
        .map(|(g, signer)| {
            json!({
                "name": names.get(&signer).cloned().unwrap_or_else(|| account::short_key(&signer)),
                "addresses": g.endpoints.iter().map(Endpoint::to_string).collect::<Vec<_>>(),
                "key": sheet_key(g.link_key.x25519()),
            })
        })
        .collect();
    Ok(json!({"hosts": hosts}))
}

/// Serves a stream of the storage service.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    let Some(v) = st.recv_message_max(4096).await? else {
        return Ok(());
    };
    let op = v
        .as_record()
        .and_then(|r| r.get(0))
        .and_then(Value::as_uint);
    let reply = match op {
        Some(OP_PROVE) => match prove(d, s, &v) {
            Some(id) => {
                tracing::info!("a new device proved it holds the recovery words");
                Record::new().with(0, OP_PROVE).with(1, id)
            }
            None => error(NOT_PERMITTED),
        },
        _ if is_unproven(d, s) => {
            s.close("prove first");
            return Ok(());
        }
        _ => error(UNKNOWN),
    };
    st.send_message(&Value::Record(reply)).await?;
    st.shutdown().await?;
    Ok(())
}

fn error(code: u64) -> Record {
    Record::new().with(0, OP_ERROR).with(1, code)
}

/// Checks a `prove`: a root key of the identity this device serves, and
/// its signature over this session.
fn prove(d: &Daemon, s: &Session, v: &Value) -> Option<[u8; 32]> {
    let r = v.as_record()?;
    let root: [u8; 32] = r.get(1)?.as_bytes()?.try_into().ok()?;
    let signature: [u8; 64] = r.get(2)?.as_bytes()?.try_into().ok()?;
    verify(&root, &proof_message(s), &signature).ok()?;
    let id = {
        let core = d.core();
        let ident = core.identity.as_ref()?;
        if ident.state().power(&root) != Some(Power::Root) {
            return None;
        }
        ident.id()
    };
    d.set_proven(s.peer_static());
    Some(id)
}

fn proof_message(s: &Session) -> Vec<u8> {
    let mut msg = PROVE_CONTEXT.to_vec();
    msg.extend_from_slice(&s.handshake_hash());
    msg
}

async fn send_proof(s: &Session, root: &SigningKey) -> anyhow::Result<Option<[u8; 32]>> {
    let mut st = s.open_stream(Service::STORAGE, Priority::Interactive)?;
    let request = Record::new()
        .with(0, OP_PROVE)
        .with(1, root.public_key())
        .with(2, root.sign(&proof_message(s)));
    st.send_message(&Value::Record(request)).await?;
    let reply = tokio::time::timeout(Duration::from_secs(20), st.recv_message_max(4096))
        .await
        .map_err(|_| anyhow::anyhow!("that device did not answer"))??
        .ok_or_else(|| anyhow::anyhow!("that device closed the connection"))?;
    let r = reply
        .as_record()
        .ok_or_else(|| anyhow::anyhow!("that device sent something unexpected"))?;
    if r.get(0).and_then(Value::as_uint) != Some(OP_PROVE) {
        return Ok(None);
    }
    let id = r
        .get(1)
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok());
    Ok(id)
}

/// What a failed connection to a host means, as far as it can be told. A
/// host says nothing to a key that is not its own, so a connection that
/// opens and then stays silent is all there is to see of a wrong key.
async fn not_reached(at: &str, addr: SocketAddr, e: LinkError) -> anyhow::Error {
    let open = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .is_ok_and(|c| c.is_ok());
    match e {
        LinkError::Timeout if open => anyhow::anyhow!(
            "a device at {at} does not answer to that key. Check the key against your recovery \
             sheet; that device may also have stopped being a host."
        ),
        LinkError::Timeout => anyhow::anyhow!(
            "no answer from {at}. Check the address against your recovery sheet, that the device \
             is on, and that no firewall is in the way."
        ),
        LinkError::Io(e) => anyhow::anyhow!(
            "nothing is listening at {at} ({e}). Check the address against your recovery sheet, \
             and that the device is on."
        ),
        e => anyhow::anyhow!("could not restore from {at}: {e}"),
    }
}

/// Restores this device from a host (`hosts.md#restore`): the recovery
/// words and the host's address and key, from the recovery sheet.
pub async fn restore(d: &Arc<Daemon>, words: &str, at: &str, key: &str) -> anyhow::Result<Json> {
    if d.core().identity.is_some() {
        anyhow::bail!("this device already belongs to someone. Nothing was changed.");
    }
    let phrase = RecoveryPhrase::parse(words).map_err(|e| anyhow::anyhow!("{e}"))?;
    let root = phrase.root_signing_key();
    let host = read_sheet_key(key).ok_or_else(|| {
        anyhow::anyhow!("that key does not check out; a character was probably mistyped")
    })?;
    let endpoint = Endpoint::parse(at).ok_or_else(|| {
        anyhow::anyhow!("{at} is not an address; it looks like 192.168.1.20:7171")
    })?;
    // A name can have several addresses, and not all of them need work.
    let addrs = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
        .await
        .map(|a| a.collect::<Vec<SocketAddr>>())
        .unwrap_or_default();
    let mut failed = anyhow::anyhow!("cannot find {at}");
    let mut found = None;
    for addr in addrs {
        let target = Target::public(addr, CarrierKind::Tcp, host);
        match d.endpoint.connect(target).await {
            Ok(s) => {
                found = Some((s, addr));
                break;
            }
            Err(e) => failed = not_reached(at, addr, e).await,
        }
    }
    let Some((s, addr)) = found else {
        return Err(failed);
    };
    let identity = send_proof(&s, &root).await?.ok_or_else(|| {
        anyhow::anyhow!("that device does not know these recovery words; nothing was changed")
    })?;
    let host_key = s
        .peer_identity()
        .ok_or_else(|| anyhow::anyhow!("that device did not say who it is"))?
        .signing_key;
    *d.pairing.lock().unwrap_or_else(|e| e.into_inner()) = PairState::Joining {
        identity,
        admin_static: host,
        admin_name: at.to_owned(),
        admin_key: host_key,
        admin_addr: Some(addr),
    };
    d.on_session(s.clone());
    // The log, then this device in it, signed by the root.
    let label = identity_log_label(&identity);
    net::reconcile(d, &s, label).await?;
    let (entry, id) = d.core().add_restoring_device(&identity, &phrase)?;
    net::deliver(&s, label, entry.clone(), id).await?;
    d.ingest(label, vec![entry], Access::Join(identity))?;
    Ok(json!({"at": at}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sheet_key_reads_back_however_it_is_typed() {
        let key = [0x5a; 32];
        let s = sheet_key(&key);
        assert_eq!(s.len(), 56 + 13, "14 groups of 4: {s}");
        assert_eq!(read_sheet_key(&s), Some(key));
        assert_eq!(read_sheet_key(&s.to_uppercase()), Some(key));
        assert_eq!(read_sheet_key(&s.replace('-', " ")), Some(key));
        assert_eq!(read_sheet_key(&s.replace('-', "")), Some(key));
        // letters that read like digits
        let k = sheet_key(&[1; 32]);
        assert_eq!(read_sheet_key(&k.replace('1', "l")), Some([1; 32]));
        assert_eq!(read_sheet_key(&k.replace('0', "o")), Some([1; 32]));
    }

    #[test]
    fn an_address_that_cannot_reach_this_device_is_pointed_out() {
        let e = |s| Endpoint::parse(s).unwrap();
        let warning = |s| address_warning(&e(s), 7171);
        assert_eq!(warning("127.0.0.1:7171"), None);
        assert!(warning("127.0.0.1:7172").unwrap().contains("port 7171"));
        // Nothing here has this address.
        assert!(warning("10.255.255.1:7171")
            .unwrap()
            .contains("not an address of this device"));
        // A router's, or a name: only the other end could tell.
        assert_eq!(warning("203.0.113.9:7171"), None);
        assert_eq!(warning("home.example.org:7171"), None);
    }

    #[test]
    fn only_a_user_service_without_linger_stops_at_logout() {
        let user = "0::/user.slice/user-1001.slice/user@1001.service/app.slice/cardinal.service\n";
        assert!(stops_at_logout(user, "no\n"));
        assert!(!stops_at_logout(user, "yes\n"));
        assert!(!stops_at_logout(
            "0::/system.slice/cardinal.service\n",
            "no\n"
        ));
        assert!(!stops_at_logout(user, ""), "no answer from loginctl");
    }

    #[test]
    fn a_slip_in_a_sheet_key_is_caught() {
        let s = sheet_key(&[7; 32]);
        for at in [0, 10, 30, s.len() - 1] {
            let mut t: Vec<char> = s.chars().collect();
            if t[at] == '-' {
                continue;
            }
            t[at] = if t[at] == '2' { '3' } else { '2' };
            let t: String = t.into_iter().collect();
            assert_eq!(read_sheet_key(&t), None, "{t}");
        }
        assert_eq!(read_sheet_key("not a key"), None);
        assert_eq!(read_sheet_key(""), None);
    }
}
