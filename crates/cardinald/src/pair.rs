//! Adding a device (`contact.md#pairing`, "adding your own device").
//!
//! The new device shows a code ([`show`]); an admin device that already
//! belongs to the person types it ([`type_code`]), having chosen the power
//! the new device joins at, which it sends, and the new device signs for
//! exactly that. The admin then adds the new device to the identity log,
//! names it in the account space, and opens a link session with the
//! pairing secret, over which the new device receives the log. Once the log
//! names it, the new device reconnects as a member and everything syncs.
//!
//! Both carriers at once: the LAN (multicast DNS and UDP), and, where
//! Bluetooth is on, the tag made from the code's channel, with the pairing
//! and then the link session on one L2CAP channel. Over Bluetooth the admin
//! dials the new device again once it has joined, since a new device knows
//! no address of the admin's there.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_contact::discovery::{advertise_pairing, find_pairing};
use cardinal_contact::pairing::{POWER_ADMIN, POWER_DEVICE};
use cardinal_contact::{
    pair_typer, pair_typer_on, EndpointAddr, LocalDevice, Paired, PairingCode, Shower,
};
use cardinal_identity::{KeyRequest, Power};
use cardinal_link::{CarrierKind, ExpectedPeer, Target};
use cardinal_space::account;

use crate::daemon::{local_ips, Daemon, PairState};

fn local_device(d: &Daemon, identity: Option<[u8; 32]>, adds_at: Option<u64>) -> LocalDevice {
    // An unspecified address means "where you reached my pairing socket".
    let addr = d
        .endpoint
        .tcp_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    LocalDevice {
        identity,
        signing_key: d.keys.signing.clone(),
        link_key: d.keys.link.public_key().clone(),
        link_endpoint: EndpointAddr::new(CarrierKind::Tcp, addr),
        name: d.config().name.clone(),
        adds_at,
    }
}

/// What the new device shows.
pub struct Shown {
    /// The code.
    pub code: String,
    /// Addresses an admin device can use with `--at` if discovery fails.
    pub addrs: Vec<SocketAddr>,
}

/// Starts showing a pairing code on a device that belongs to no one. The
/// admin device that types it says at what power this one joins.
pub async fn show(d: &Arc<Daemon>) -> anyhow::Result<Shown> {
    if d.core().identity.is_some() {
        anyhow::bail!(
            "this device already belongs to you. To add another device, run `cardinal pair` \
             on the new device and type its code here with `cardinal pair <code>`."
        );
    }
    let local = local_device(d, None, None);
    let shower = Shower::bind(local, "0.0.0.0:0".parse().expect("addr"), None).await?;
    let code = shower.code().clone();
    // Over Bluetooth too, whenever it is on while the code shows.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    crate::bluetooth::show_pairing(d, code.channel, tx);
    let shower = shower.with_channels(rx);
    let port = shower.local_addr()?.port();
    let ad = match advertise_pairing(d.mdns_config(), code.channel, port, Duration::from_secs(1)) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!("cannot advertise the pairing code on the LAN: {e}");
            None
        }
    };
    let mut addrs: Vec<SocketAddr> = local_ips()
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    addrs.push(SocketAddr::from(([127, 0, 0, 1], port)));
    *d.pairing.lock().unwrap_or_else(|e| e.into_inner()) = PairState::Showing {
        code: code.to_string(),
    };
    let d2 = d.clone();
    tokio::spawn(async move {
        let r = shower.run().await;
        drop(ad);
        crate::bluetooth::stop_pairing(&d2);
        let mut ps = d2.pairing.lock().unwrap_or_else(|e| e.into_inner());
        match r {
            Ok(mut p) => {
                let Some(identity) = p.peer.identity else {
                    *ps = PairState::Failed("the other device has no identity".into());
                    return;
                };
                d2.endpoint.add_secret(p.secret_entry());
                // Over Bluetooth, the link session follows on the channel.
                if let Some(ch) = p.channel.take() {
                    crate::bluetooth::carry(&d2, ch, "bluetooth pairing".into());
                }
                let power = p.joins_at.and_then(Power::from_u64);
                tracing::info!(
                    "paired with {}; waiting for it to add this device as {}",
                    p.peer.name,
                    power_words(power)
                );
                *ps = PairState::Joining {
                    identity,
                    admin_static: *p.peer.link_key.x25519(),
                    admin_name: p.peer.name.clone(),
                    admin_key: p.peer.signing_key,
                    admin_addr: p.peer.endpoint.socket_addr(),
                    power,
                };
            }
            Err(e) => {
                tracing::warn!("pairing failed: {e}");
                *ps = PairState::Failed(match e {
                    cardinal_contact::ContactError::TooManyAttempts => {
                        "the code was typed wrong too often; run `cardinal pair` again for a new code"
                            .into()
                    }
                    cardinal_contact::ContactError::Timeout => {
                        "no device typed the code in time; run `cardinal pair` again".into()
                    }
                    cardinal_contact::ContactError::Malformed(w) => format!(
                        "the device that typed the code sent a {w}: is it running an older \
                         version? Update it and run `cardinal pair` again"
                    ),
                    e => e.to_string(),
                });
            }
        }
    });
    Ok(Shown {
        code: code.to_string(),
        addrs,
    })
}

/// Types a code shown by a new device and adds that device, named `device`
/// if given and else as it names itself. Returns the new device's name.
/// Neither changes the name the person suggests for themselves.
pub async fn type_code(
    d: &Arc<Daemon>,
    code: &str,
    at: Option<SocketAddr>,
    admin: bool,
    words: Option<&str>,
    device: Option<&str>,
) -> anyhow::Result<String> {
    let identity = d.core().identity.as_ref().map(|i| i.id()).ok_or_else(|| {
        anyhow::anyhow!(
            "this device does not belong to anyone yet. Run `cardinal init` here first, \
             or run `cardinal pair` (without a code) to add this device to your others."
        )
    })?;
    // Only an admin device adds devices, or the recovery words.
    let root = crate::recovery::signer(
        d,
        words,
        |mine| mine >= Some(Power::Admin),
        || "this device cannot add devices (it is not an admin device)".to_owned(),
    )?;
    let code = PairingCode::parse(code).map_err(|_| {
        anyhow::anyhow!("{code:?} is not a pairing code; it looks like 4-anchor-harbor-quit")
    })?;
    let power = if admin { Power::Admin } else { Power::Device };
    let adds_at = if admin { POWER_ADMIN } else { POWER_DEVICE };
    let local = local_device(d, Some(identity), Some(adds_at));
    let (paired, over) = match at {
        Some(addr) => (pair_on_lan(&local, &code, addr).await?, Over::Lan(addr)),
        None => find_and_pair(d, &local, &code).await?,
    };
    let mut nd = paired.new_device.clone().ok_or_else(|| {
        anyhow::anyhow!("that device already belongs to someone; it cannot be added")
    })?;
    if let Some(name) = device {
        nd.name = name.to_owned();
    }
    // `pair_typer` refused a proof for any other power than the one sent.
    debug_assert_eq!(nd.power, adds_at);
    // Add it to the identity log, with a wrap of the encryption key.
    let entry = {
        let mut core = d.core();
        let ident = core.identity.as_mut().expect("identity");
        let enc = ident
            .enc
            .first()
            .ok_or_else(|| anyhow::anyhow!("cannot open this identity's encryption key"))?;
        let enc = cardinal_crypto::HybridKeyPair::from_secret_bytes(&enc.secret_bytes());
        let req = KeyRequest {
            key: nd.signing_key,
            power,
            link_key: nd.link_key.clone(),
            proof: nd.proof,
        };
        let signer = root.as_ref().unwrap_or(&d.keys.device.signing);
        let e = ident.log.add_key(signer, &req, Some(&enc))?;
        ident.record_own(&e)?;
        e
    };
    d.identity_changed();
    d.push_identity(vec![entry.encode()]);
    // Name it in the account space, by a name none of the person's other
    // devices has: a device is also found by its name.
    let (acc, others) = {
        let core = d.core();
        let others: Vec<String> = core
            .account()
            .and_then(|h| h.space.as_ref())
            .map(|sp| {
                account::devices(sp.state())
                    .into_iter()
                    .map(|r| r.name)
                    .collect()
            })
            .unwrap_or_default();
        (core.account_id(), others)
    };
    if let Some(acc) = acc {
        let name = crate::daemon::unique_name(&nd.name, &others);
        d.write_and_push(
            &acc,
            vec![account::create_device(&nd.signing_key, &name, false, false)],
        )?;
    }
    let s = match over {
        Over::Lan(addr) => {
            let secret = zeroize::Zeroizing::new(paired.link_secret.to_vec());
            let endpoint = paired.peer.endpoint.socket_addr();
            link_on_lan(d, endpoint, &secret, &nd, addr).await?
        }
        Over::Ble(seen, ch) => {
            let on = crate::bluetooth::carry(d, ch, format!("bluetooth pairing {}", seen.addr));
            let s = d
                .endpoint
                .connect_on(&on, paired.target_on(CarrierKind::Ble))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "added the device, but the session over Bluetooth failed ({e}). Run \
                         `cardinal pair` on it again."
                    )
                })?;
            tokio::spawn(dial_again(d.clone(), s.clone(), seen, nd.link_key.clone()));
            s
        }
    };
    d.on_session(s);
    tracing::info!("added {} as a {:?} device", nd.name, power);
    Ok(nd.name)
}

/// Where a pairing ran.
enum Over {
    Lan(SocketAddr),
    Ble(crate::bluetooth::Seen, cardinal_contact::ble::BoxChannel),
}

fn power_words(p: Option<Power>) -> &'static str {
    match p {
        Some(Power::Admin) => "an admin device",
        _ => "a device",
    }
}

fn pair_error(e: cardinal_contact::ContactError) -> anyhow::Error {
    match e {
        cardinal_contact::ContactError::WrongCode => {
            anyhow::anyhow!("the code does not match the one shown; check it and try again")
        }
        cardinal_contact::ContactError::Timeout => {
            anyhow::anyhow!("the new device did not answer; is it still showing the code?")
        }
        cardinal_contact::ContactError::BadProof => anyhow::anyhow!(
            "the new device did not agree to join at the power this device chose; is it \
             running an older version?"
        ),
        e => anyhow::anyhow!("pairing failed: {e}"),
    }
}

async fn pair_on_lan(
    local: &LocalDevice,
    code: &PairingCode,
    addr: SocketAddr,
) -> anyhow::Result<Paired> {
    pair_typer(local, code, addr, Duration::from_secs(30))
        .await
        .map_err(pair_error)
}

/// Finds the device showing `code` on the LAN and, where Bluetooth is on,
/// nearby, whichever answers first, and pairs with it there.
async fn find_and_pair(
    d: &Arc<Daemon>,
    local: &LocalDevice,
    code: &PairingCode,
) -> anyhow::Result<(Paired, Over)> {
    let lan = find_pairing(d.mdns_config(), code.channel, Duration::from_secs(20));
    let ble = crate::bluetooth::find_pairing(d, code.channel);
    tokio::pin!(lan, ble);
    let (mut lan_done, mut ble_done) = (false, false);
    let mut ble_failed: Option<anyhow::Error> = None;
    loop {
        tokio::select! {
            r = &mut lan, if !lan_done => {
                lan_done = true;
                if let Ok(addr) = r {
                    return Ok((pair_on_lan(local, code, addr).await?, Over::Lan(addr)));
                }
            }
            r = &mut ble, if !ble_done => {
                ble_done = true;
                let Some(seen) = r else { continue };
                let tried = async {
                    let mut ch = crate::bluetooth::open_channel(&seen).await?;
                    match pair_typer_on(local, code, &mut ch, Duration::from_secs(30)).await {
                        Ok(p) => Ok(Ok((p, ch))),
                        Err(e) => Ok(Err(e)),
                    }
                };
                let e = match tried.await {
                    Ok(Ok((p, ch))) => return Ok((p, Over::Ble(seen, ch))),
                    // what the code or the other device decided is the
                    // same over any carrier
                    Ok(Err(
                        e @ (cardinal_contact::ContactError::WrongCode
                        | cardinal_contact::ContactError::TooManyAttempts
                        | cardinal_contact::ContactError::BadProof
                        | cardinal_contact::ContactError::NoIdentity),
                    )) => return Err(pair_error(e)),
                    Ok(Err(e)) => pair_error(e),
                    Err(e) => e,
                };
                // The radio failed it: the local network may still find
                // the device, looked for again if it gave up meanwhile.
                tracing::info!("pairing over Bluetooth failed: {e:#}; trying the local network");
                ble_failed = Some(e);
                if lan_done {
                    lan.set(find_pairing(d.mdns_config(), code.channel, Duration::from_secs(20)));
                    lan_done = false;
                }
            }
            else => break,
        }
    }
    if let Some(e) = ble_failed {
        return Err(e.context("not found on the local network either"));
    }
    anyhow::bail!(
        "could not find the device showing that code on the local network{}. Are both on the \
         same network? You can also give its address: \
         `cardinal pair <code> --at <address shown on the new device>`",
        if crate::bluetooth::is_running(d) {
            " or over Bluetooth"
        } else {
            ""
        }
    )
}

/// Over Bluetooth the new device knows no address of this one's: once the
/// pairing session ends, as it does when the new device has joined, this
/// device dials it again where it was, as one of the person's own.
async fn dial_again(
    d: Arc<Daemon>,
    pairing: cardinal_link::Session,
    seen: crate::bluetooth::Seen,
    link_key: cardinal_crypto::HybridPublicKey,
) {
    pairing.closed().await;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if d.is_online(link_key.x25519()) {
            return;
        }
        match crate::bluetooth::dial(&d, &seen, std::slice::from_ref(&link_key)).await {
            Ok(s) => {
                d.on_session(s);
                return;
            }
            Err(e) => tracing::debug!("Bluetooth: the new device at {}: {e:#}", seen.addr),
        }
    }
}

/// The link session with a device paired on the LAN: at its advertised
/// endpoint, at the address reached.
async fn link_on_lan(
    d: &Arc<Daemon>,
    endpoint: Option<SocketAddr>,
    secret: &[u8],
    nd: &cardinal_contact::NewDevice,
    addr: SocketAddr,
) -> anyhow::Result<cardinal_link::Session> {
    // Where it listens: its advertised endpoint, at the address we reached.
    let mut link_addr = endpoint.unwrap_or_else(|| SocketAddr::new(addr.ip(), 0));
    if link_addr.ip().is_unspecified() {
        link_addr.set_ip(addr.ip());
    }
    let mut candidates = vec![link_addr];
    let alt = SocketAddr::new(addr.ip(), link_addr.port());
    if alt != link_addr {
        candidates.push(alt);
    }
    let mut last = String::new();
    let mut session = None;
    'outer: for _ in 0..10 {
        for a in &candidates {
            let target = Target::new(*a, CarrierKind::Tcp, &nd.link_key)
                .with_secret(secret)
                .expect(ExpectedPeer {
                    identity: None,
                    signing_key: Some(nd.signing_key),
                    no_identity: true,
                });
            match d.endpoint.connect(target).await {
                Ok(s) => {
                    d.learn_addr(&nd.signing_key, *a);
                    session = Some(s);
                    break 'outer;
                }
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    session.ok_or_else(|| {
        anyhow::anyhow!(
            "added the device, but could not reach it ({last}). Check that it is running and \
             reachable, then run `cardinal pair` on it again."
        )
    })
}
