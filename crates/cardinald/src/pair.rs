//! Adding a device (`contact.md#pairing`, "adding your own device").
//!
//! The new device shows a code ([`show`]); an admin device that already
//! belongs to the person types it ([`type_code`]). The admin then adds the
//! new device to the identity log, names it in the account space, and
//! opens a link session with the pairing secret, over which the new device
//! receives the log. Once the log names it, the new device reconnects as a
//! member and everything syncs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_contact::discovery::{advertise_pairing, find_pairing};
use cardinal_contact::pairing::{POWER_ADMIN, POWER_DEVICE};
use cardinal_contact::{pair_typer, EndpointAddr, LocalDevice, PairingCode, Shower};
use cardinal_identity::{KeyRequest, Power};
use cardinal_link::{CarrierKind, ExpectedPeer, Target};
use cardinal_space::account;

use crate::daemon::{local_ips, Daemon, PairState};

fn local_device(d: &Daemon, identity: Option<[u8; 32]>, power: u64) -> LocalDevice {
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
        join_power: power,
    }
}

/// What the new device shows.
pub struct Shown {
    /// The code.
    pub code: String,
    /// Addresses an admin device can use with `--at` if discovery fails.
    pub addrs: Vec<SocketAddr>,
}

/// Starts showing a pairing code on a device that belongs to no one.
pub async fn show(d: &Arc<Daemon>, admin: bool) -> anyhow::Result<Shown> {
    if d.core().identity.is_some() {
        anyhow::bail!(
            "this device already belongs to you. To add another device, run `cardinal pair` \
             on the new device and type its code here with `cardinal pair <code>`."
        );
    }
    let power = if admin { POWER_ADMIN } else { POWER_DEVICE };
    let local = local_device(d, None, power);
    let shower = Shower::bind(local, "0.0.0.0:0".parse().expect("addr"), None).await?;
    let code = shower.code().clone();
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
        let mut ps = d2.pairing.lock().unwrap_or_else(|e| e.into_inner());
        match r {
            Ok(p) => {
                let Some(identity) = p.peer.identity else {
                    *ps = PairState::Failed("the other device has no identity".into());
                    return;
                };
                d2.endpoint.add_secret(p.secret_entry());
                tracing::info!(
                    "paired with {}; waiting for it to add this device",
                    p.peer.name
                );
                *ps = PairState::Joining {
                    identity,
                    admin_static: *p.peer.link_key.x25519(),
                    admin_name: p.peer.name.clone(),
                    admin_key: p.peer.signing_key,
                    admin_addr: p.peer.endpoint.socket_addr(),
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

/// Types a code shown by a new device and adds that device. Returns the
/// new device's name.
pub async fn type_code(
    d: &Arc<Daemon>,
    code: &str,
    at: Option<SocketAddr>,
    admin: bool,
    words: Option<&str>,
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
    let addr = match at {
        Some(a) => a,
        None => find_pairing(d.mdns_config(), code.channel, Duration::from_secs(20))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "could not find the device showing that code on the local network. Are both \
                     on the same network? You can also give its address: \
                     `cardinal pair <code> --at <address shown on the new device>`"
                )
            })?,
    };
    let local = local_device(d, Some(identity), POWER_DEVICE);
    let paired = pair_typer(&local, &code, addr, Duration::from_secs(30))
        .await
        .map_err(|e| match e {
            cardinal_contact::ContactError::WrongCode => {
                anyhow::anyhow!("the code does not match the one shown; check it and try again")
            }
            cardinal_contact::ContactError::Timeout => {
                anyhow::anyhow!("the new device did not answer; is it still showing the code?")
            }
            e => anyhow::anyhow!("pairing failed: {e}"),
        })?;
    let nd = paired.new_device.clone().ok_or_else(|| {
        anyhow::anyhow!("that device already belongs to someone; it cannot be added")
    })?;
    let power = if admin {
        Power::Admin
    } else {
        Power::from_u64(nd.power).unwrap_or(Power::Device)
    };
    if power != Power::from_u64(nd.power).unwrap_or(Power::Device) {
        anyhow::bail!(
            "the new device asked for a different power; run `cardinal pair --admin` on it \
             to make it an admin device"
        );
    }
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
    // Name it in the account space.
    let acc = d.core().account_id();
    if let Some(acc) = acc {
        d.write_and_push(
            &acc,
            vec![account::create_device(
                &nd.signing_key,
                &nd.name,
                false,
                false,
            )],
        )?;
    }
    // Where it listens: its advertised endpoint, at the address we reached.
    let mut link_addr = paired
        .peer
        .endpoint
        .socket_addr()
        .unwrap_or_else(|| SocketAddr::new(addr.ip(), 0));
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
                .with_secret(&paired.link_secret[..])
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
    let s = session.ok_or_else(|| {
        anyhow::anyhow!(
            "added the device, but could not reach it ({last}). Check that it is running and \
             reachable, then run `cardinal pair` on it again."
        )
    })?;
    d.on_session(s);
    tracing::info!("added {} as a {:?} device", nd.name, power);
    Ok(nd.name)
}
