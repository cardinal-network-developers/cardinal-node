//! Introductions (`contact.md#introductions`), and those a group makes
//! (`profiles.md#group`).
//!
//! Carol introduces Ana to Ben with a node in her space with Ben. If Ben says
//! yes, his device puts an invitation for Ana alone in it, and Carol's devices
//! pass it to Ana in her space with Ana, who uses it if she says yes too.
//!
//! In a group the admin is the introducer. A member who would like to meet
//! another asks with a node in their space with an admin, naming the group;
//! the admin's devices make the introduction unasked, unless the group or
//! either member says not to, and pass Ben's invitation back in that node,
//! which Ana's device then uses, since she asked.

use std::sync::Arc;
use std::time::Duration;

use cardinal_contact::Invitation;
use cardinal_space::account::{self, ContactRecord, Met, Regard};
use cardinal_space::group;
use cardinal_space::relationship::{self, Introduction};
use cardinal_space::{SpaceId, SpaceOp};
use serde_json::{json, Value as Json};

use crate::api::Ref;
use crate::contacts::{self, identity};
use crate::daemon::Daemon;

/// A trusted contact, and someone this person may introduce or be
/// introduced through: not refused, and not set to no introductions.
fn introduces(c: &ContactRecord) -> bool {
    c.connects() && c.regard.introductions
}

/// An introduction's invitation, if it is what it must be: made by `from`,
/// for `to` alone. Anyone in the space can write one in, so it is checked
/// before it is passed on or used.
fn invitation_from(
    record: Option<&cardinal_encoding::Record>,
    from: &[u8; 32],
    to: &[u8; 32],
) -> Option<cardinal_encoding::Record> {
    let record = record?;
    let inv = Invitation::from_record(record).ok()?;
    // never a recovery's (`guardians.rs`)
    (inv.inviter == *from && inv.for_identity == Some(*to) && inv.recovery_of.is_none())
        .then(|| record.clone())
}

fn met_through(introducer: [u8; 32], group: Option<SpaceId>) -> Met {
    Met {
        how: account::MET_INTRODUCED,
        introducer: Some(introducer),
        group,
        via: None,
    }
}

/// Introduces the contact `who` to the contact `to`.
pub fn introduce(d: &Arc<Daemon>, who: &str, to: &str, note: Option<&str>) -> anyhow::Result<Json> {
    let me = identity(d)?;
    let x = contacts::listed(d, who)?;
    let b = contacts::listed(d, to)?;
    anyhow::ensure!(x.identity != b.identity, "that is one person");
    for c in [&x, &b] {
        anyhow::ensure!(
            introduces(c),
            "you do not introduce {}: they are not trusted, or set to no introductions",
            c.petname
        );
    }
    // the name they suggest, never this person's own for them
    let suggested = x.suggested.as_deref().unwrap_or(&x.petname);
    let op = relationship::create_introduction(&me, &x.identity, suggested, note, None, None);
    d.write_and_push(&b.space, vec![op])?;
    Ok(json!({}))
}

/// Asks to meet a member of a group, through an admin of it who knows both.
pub fn ask_in_group(
    d: &Arc<Daemon>,
    group_name: &str,
    who: &str,
    note: Option<&str>,
) -> anyhow::Result<Json> {
    let me = identity(d)?;
    let (space, them, shown, admins) = {
        let core = d.core();
        let groups = core.spaces.iter().filter_map(|(id, h)| {
            let sp = h.space.as_ref()?;
            (sp.profile() == group::GROUP).then_some((id, sp))
        });
        // as bytes, the group and the member whose ids they are
        let (asked, person) = (
            crate::api::reference(group_name),
            crate::api::reference(who),
        );
        let found: Vec<_> = groups
            .filter(|(id, sp)| match asked {
                Ref::Id(_) => asked.is_id(id.as_slice()),
                Ref::Typed(_) => {
                    group::name(sp) == group_name
                        || (group_name.len() >= 8 && hex::encode(id).starts_with(group_name))
                }
            })
            .collect();
        let (group_name, who) = (crate::api::shown(group_name), crate::api::shown(who));
        let [(id, sp)] = found.as_slice() else {
            anyhow::bail!("there is no one group {group_name}");
        };
        let members = group::members(sp);
        let them = members
            .iter()
            .find(|m| {
                let meant = match person {
                    Ref::Id(_) => person.is_id(&m.identity),
                    Ref::Typed(_) => m.name.as_deref() == Some(who),
                };
                meant && m.identity != me
            })
            .ok_or_else(|| anyhow::anyhow!("nobody in it is called {who}"))?;
        anyhow::ensure!(
            group::introductions(sp),
            "{group_name} does not introduce its members"
        );
        anyhow::ensure!(
            them.introduce,
            "{who} is not introduced through {group_name}"
        );
        let admins: Vec<[u8; 32]> = members
            .iter()
            .filter(|m| m.role >= group::ADMIN && m.identity != me)
            .map(|m| m.identity)
            .collect();
        (
            **id,
            them.identity,
            them.name.clone().unwrap_or_default(),
            admins,
        )
    };
    anyhow::ensure!(
        !d.core().contacts().iter().any(|c| c.identity == them),
        "you know {who} already"
    );
    let contacts = d.core().contacts();
    let admin = contacts
        .iter()
        .find(|c| admins.contains(&c.identity) && introduces(c))
        .ok_or_else(|| {
            anyhow::anyhow!("no admin of {group_name} that you know can introduce you")
        })?;
    // Asked already, and not answered: asking again changes nothing.
    let asked = {
        let core = d.core();
        let sp = core.spaces.get(&admin.space).and_then(|h| h.space.as_ref());
        sp.is_some_and(|sp| {
            relationship::introductions(sp).iter().any(|i| {
                i.creator == me && i.introduced == them && i.group == Some(space) && !i.declined
            })
        })
    };
    if asked {
        return Ok(json!({"asked": true}));
    }
    let op =
        relationship::create_introduction(&admin.identity, &them, &shown, note, Some(&space), None);
    d.write_and_push(&admin.space, vec![op])?;
    Ok(json!({}))
}

/// An introduction this person may answer, where it is, and what it is.
struct Waiting {
    space: SpaceId,
    from: ContactRecord,
    intro: Introduction,
}

/// The introductions waiting for this person to answer: someone would like
/// them to meet someone, or has introduced them to someone who said yes.
fn waiting(d: &Daemon) -> Vec<Waiting> {
    let Ok(me) = identity(d) else {
        return Vec::new();
    };
    let core = d.core();
    let contacts = core.contacts();
    let mut out = Vec::new();
    for c in contacts.iter().filter(|c| introduces(c)) {
        let Some(sp) = core.spaces.get(&c.space).and_then(|h| h.space.as_ref()) else {
            continue;
        };
        for mut i in relationship::introductions(sp) {
            let theirs = i.introducer == c.identity && i.creator == c.identity;
            let known = contacts.iter().any(|k| k.identity == i.introduced);
            // One this person said yes to holds their own invitation: the
            // other side answers it, not them.
            let answered = i
                .invitation
                .as_ref()
                .is_some_and(|r| Invitation::from_record(r).is_ok_and(|inv| inv.inviter == me));
            // Only theirs, for this person, is anything to connect with.
            i.invitation = invitation_from(i.invitation.as_ref(), &i.introduced, &me);
            if theirs && !i.declined && !known && !answered && i.introduced != me {
                out.push(Waiting {
                    space: c.space,
                    from: c.clone(),
                    intro: i,
                });
            }
        }
    }
    out
}

fn group_name(d: &Daemon, g: Option<SpaceId>) -> Option<String> {
    let core = d.core();
    let sp = core.spaces.get(&g?)?.space.as_ref()?;
    Some(group::name(sp))
}

/// The introductions waiting for this person, as a window shows them.
pub fn list(d: &Daemon) -> Json {
    let all: Vec<Json> = waiting(d)
        .into_iter()
        .map(|w| {
            json!({
                "id": hex::encode(w.intro.node),
                "from": w.from.petname,
                "name": w.intro.name,
                "note": w.intro.note,
                "group": group_name(d, w.intro.group),
                // `meet`: say whether to meet them; `introduced`: they said
                // yes already, and this connects.
                "kind": if w.intro.invitation.is_some() { "introduced" } else { "meet" },
            })
        })
        .collect();
    json!({"introductions": all})
}

fn find(d: &Daemon, id: &str) -> anyhow::Result<Waiting> {
    let id = crate::api::id_hex(id);
    let found = waiting(d)
        .into_iter()
        .find(|w| hex::encode(w.intro.node) == id);
    found.ok_or_else(|| anyhow::anyhow!("there is no such introduction"))
}

/// Says yes to an introduction: an invitation for the one introduced, or,
/// once they said yes too, using theirs.
pub async fn accept(d: &Arc<Daemon>, id: &str) -> anyhow::Result<Json> {
    let w = find(d, id)?;
    let met = met_through(w.from.identity, w.intro.group);
    match &w.intro.invitation {
        None => {
            let me_as = crate::names::my_name(d);
            let invitation = contacts::invite_for(
                d,
                None,
                Some(&me_as),
                Regard::default(),
                Some(w.intro.introduced),
                Some(&met),
            )?;
            let ops = relationship::answer_introduction(w.intro.node, invitation.to_record(), None);
            d.write_and_push(&w.space, ops)?;
            Ok(json!({}))
        }
        Some(record) => use_invitation(d, record, &w.intro.name, met).await,
    }
}

async fn use_invitation(
    d: &Arc<Daemon>,
    record: &cardinal_encoding::Record,
    name: &str,
    met: Met,
) -> anyhow::Result<Json> {
    let invitation = Invitation::from_record(record)
        .map_err(|_| anyhow::anyhow!("that invitation cannot be read"))?;
    // A recovery's invitation is never an introduction's (`guardians.rs`).
    anyhow::ensure!(
        invitation.recovery_of.is_none(),
        "that introduction carries a recovery invitation, which is never used for one"
    );
    let name = (!name.is_empty()).then_some(name);
    contacts::accept(
        d,
        &invitation.to_text(),
        name,
        Regard::default(),
        met,
        false,
    )
    .await
}

/// Says no to an introduction. The introducer sees that.
pub fn decline(d: &Arc<Daemon>, id: &str) -> anyhow::Result<Json> {
    let w = find(d, id)?;
    d.write_and_push(
        &w.space,
        vec![relationship::decline_introduction(w.intro.node)],
    )?;
    Ok(json!({}))
}

/// What this person's devices do of themselves: pass on the yes of someone
/// they introduced, introduce the members of their groups who ask, and use
/// the invitation that comes back for one this person asked for.
async fn tend(d: &Arc<Daemon>) {
    let Ok(me) = identity(d) else {
        return;
    };
    let contacts = d.core().contacts();
    let mut writes: Vec<(SpaceId, Vec<SpaceOp>)> = Vec::new();
    let mut uses: Vec<(cardinal_encoding::Record, String, Met)> = Vec::new();
    {
        let core = d.core();
        let intros_of = |c: &ContactRecord| -> Vec<Introduction> {
            let sp = core.spaces.get(&c.space).and_then(|h| h.space.as_ref());
            sp.map(relationship::introductions).unwrap_or_default()
        };
        for b in contacts.iter().filter(|c| introduces(c)) {
            for n in intros_of(b) {
                // Ben said yes to one this person made: Ana hears of it.
                if n.creator == me && n.introducer == me {
                    // Only an answer: theirs, for the one introduced.
                    let answer = invitation_from(n.invitation.as_ref(), &b.identity, &n.introduced);
                    let (Some(invitation), Some(x)) = (
                        answer,
                        contacts
                            .iter()
                            .find(|c| c.identity == n.introduced && introduces(c)),
                    ) else {
                        continue;
                    };
                    let there = intros_of(x);
                    let done = there
                        .iter()
                        .any(|m| m.invitation.as_ref() == Some(&invitation));
                    if done {
                        continue;
                    }
                    let asked = there.iter().find(|m| {
                        m.creator == x.identity
                            && m.introducer == me
                            && m.introduced == b.identity
                            && m.invitation.is_none()
                    });
                    let ops = match asked {
                        Some(m) => relationship::answer_introduction(m.node, invitation, None),
                        None => vec![relationship::create_introduction(
                            &me,
                            &b.identity,
                            b.suggested.as_deref().unwrap_or(&b.petname),
                            n.note.as_deref(),
                            n.group.as_ref(),
                            Some(invitation),
                        )],
                    };
                    writes.push((x.space, ops));
                }
                // A member of a group asks this person, its admin, to meet
                // another: done unasked, if the group lets it.
                if n.creator == b.identity
                    && n.introducer == me
                    && n.invitation.is_none()
                    && !n.declined
                {
                    let Some(g) = n.group else {
                        continue;
                    };
                    let target = contacts
                        .iter()
                        .find(|c| c.identity == n.introduced && introduces(c));
                    let allowed = target.is_some() && {
                        let sp = core.spaces.get(&g).and_then(|h| h.space.as_ref());
                        sp.is_some_and(|sp| {
                            let members = group::members(sp);
                            let ok = |who: &[u8; 32]| {
                                members.iter().any(|m| m.identity == *who && m.introduce)
                            };
                            let admin = group::role_of(sp, &me).is_some_and(|r| r >= group::ADMIN);
                            admin
                                && group::introductions(sp)
                                && ok(&b.identity)
                                && ok(&n.introduced)
                        })
                    };
                    let Some(t) = target.filter(|_| allowed) else {
                        writes.push((b.space, vec![relationship::decline_introduction(n.node)]));
                        continue;
                    };
                    let made = intros_of(t).iter().any(|m| {
                        m.creator == me && m.introduced == b.identity && m.group == Some(g)
                    });
                    if !made {
                        let shown = core
                            .spaces
                            .get(&g)
                            .and_then(|h| h.space.as_ref())
                            .and_then(|sp| {
                                group::members(sp)
                                    .into_iter()
                                    .find(|m| m.identity == b.identity)
                            })
                            .and_then(|m| m.name)
                            .or_else(|| b.suggested.clone())
                            .unwrap_or_else(|| b.petname.clone());
                        let op = relationship::create_introduction(
                            &me,
                            &b.identity,
                            &shown,
                            n.note.as_deref(),
                            Some(&g),
                            None,
                        );
                        writes.push((t.space, vec![op]));
                    }
                }
                // One this person asked for came back with an invitation.
                if n.creator == me && n.introducer == b.identity {
                    let known = contacts.iter().any(|c| c.identity == n.introduced);
                    // Only one from whom this person asked to meet, for them.
                    let theirs = invitation_from(n.invitation.as_ref(), &n.introduced, &me);
                    if let (Some(invitation), false) = (theirs, known) {
                        uses.push((invitation, n.name.clone(), met_through(b.identity, n.group)));
                    }
                }
            }
        }
    }
    for (space, ops) in writes {
        if let Err(e) = d.write_and_push(&space, ops) {
            tracing::debug!("introducing: {e:#}");
        }
    }
    for (invitation, name, met) in uses {
        if let Err(e) = use_invitation(d, &invitation, &name, met).await {
            tracing::debug!("using an introduction's invitation: {e:#}");
        }
    }
}

/// Keeps tending introductions whenever something changes.
pub fn start(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        loop {
            if changed.changed().await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            tend(&d).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_contact::EndpointAddr;
    use cardinal_link::CarrierKind;

    /// Only the person introduced may connect by an introduction, with an
    /// invitation of the other's made for them: one written in by anyone else,
    /// or for anyone else, is nothing.
    /// A recovery invitation is never used for an introduction, by the
    /// person's tending or by their saying yes, and `accept` takes one only
    /// when asked to, and then only as a guardian: nothing is dialled.
    #[tokio::test]
    async fn a_recovery_invitation_is_never_an_introductions() {
        let at = EndpointAddr::new(CarrierKind::Udp, "127.0.0.1:1".parse().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let (paths, config) = crate::testing::set_up(dir.path());
        let d = Daemon::start(paths, config).await.unwrap();
        let me = d.core().me().unwrap();
        let (ben, ana) = ([1u8; 32], [2u8; 32]);
        let mut inv = Invitation::new(ben, [9; 32], at);
        inv.for_identity = Some(me);
        inv.recovery_of = Some(ana);
        let r = inv.to_record();
        assert_eq!(invitation_from(Some(&r), &ben, &me), None);
        let e = use_invitation(&d, &r, "Ben", met_through(ben, None))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("never used"), "{e}");
        let met = Met::default();
        let e = contacts::accept(
            &d,
            &inv.to_text(),
            None,
            Regard::default(),
            met.clone(),
            false,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("only you"), "{e}");
        // one for whomever the guardian names, taken up without saying whom
        let mut anyone = inv.clone();
        anyone.recovery_of = Some(crate::recovering::ANYONE);
        let e = contacts::accept(
            &d,
            &anyone.to_text(),
            None,
            Regard::default(),
            Met::default(),
            true,
        )
        .await
        .unwrap_err();
        assert!(e.is::<contacts::NeedsFor>(), "{e}");
        // asked, but this person guards nobody
        let e = contacts::accept(&d, &inv.to_text(), None, Regard::default(), met, true)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not one of their guardians"), "{e}");
    }

    #[test]
    fn an_introductions_invitation_is_checked_before_use() {
        let at = EndpointAddr::new(CarrierKind::Udp, "127.0.0.1:7171".parse().unwrap());
        let (ben, ana, eve) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let mut theirs = Invitation::new(ben, [9; 32], at.clone());
        theirs.for_identity = Some(ana);
        let r = theirs.to_record();
        assert_eq!(invitation_from(Some(&r), &ben, &ana), Some(r.clone()));
        assert_eq!(
            invitation_from(Some(&r), &eve, &ana),
            None,
            "not from whom asked"
        );
        assert_eq!(
            invitation_from(Some(&r), &ben, &eve),
            None,
            "not for this one"
        );
        let mut open = Invitation::new(ben, [9; 32], at);
        open.for_identity = None;
        assert_eq!(
            invitation_from(Some(&open.to_record()), &ben, &ana),
            None,
            "for anyone"
        );
        assert_eq!(invitation_from(None, &ben, &ana), None);
    }
}
