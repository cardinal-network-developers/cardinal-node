//! Messages of the `sync` service (`sync.md#messages`).

use cardinal_encoding::{Record, SchemaError, Value};

use crate::{Fingerprint, Id, Label, SyncError};

/// What a range asks of the receiver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 0: nothing to do.
    Skip,
    /// 1: the sender's fingerprint of the range.
    Fingerprint(Fingerprint),
    /// 2: every id the sender holds in the range.
    List(Vec<Id>),
    /// 3: ids the sender holds in the range that the receiver lacks.
    YouLack(Vec<Id>),
}

impl Mode {
    /// The mode number.
    pub fn number(&self) -> u64 {
        match self {
            Mode::Skip => 0,
            Mode::Fingerprint(_) => 1,
            Mode::List(_) => 2,
            Mode::YouLack(_) => 3,
        }
    }
}

/// One range of a reconcile message: from the previous range's upper bound
/// (or the start), inclusive, to `upper`, exclusive (or the end).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// Exclusive upper bound; `None` in the final range.
    pub upper: Option<Id>,
    /// What to do with the range.
    pub mode: Mode,
}

impl Range {
    /// The record form `{1: upper bound, 2: mode, 3: payload}`.
    pub fn to_record(&self) -> Record {
        let r = Record::new()
            .with_opt(1, self.upper)
            .with(2, self.mode.number());
        match &self.mode {
            Mode::Skip => r,
            Mode::Fingerprint(f) => r.with(3, *f),
            Mode::List(ids) | Mode::YouLack(ids) => r.with(3, id_list(ids)),
        }
    }

    /// Reads the record form.
    pub fn from_record(r: &Record) -> Result<Range, SyncError> {
        let upper = r.opt_bytes_n::<32>(1)?;
        let mode = match r.uint(2)? {
            0 => Mode::Skip,
            1 => Mode::Fingerprint(r.bytes_n::<16>(3)?),
            2 => Mode::List(read_ids(r, 3)?),
            3 => Mode::YouLack(read_ids(r, 3)?),
            _ => return Err(SchemaError::Invalid("unknown range mode").into()),
        };
        Ok(Range { upper, mode })
    }

    /// Bytes this range adds to a message.
    pub fn encoded_len(&self) -> usize {
        self.to_record().encoded_len()
    }
}

fn id_list(ids: &[Id]) -> Value {
    Value::List(ids.iter().map(|id| Value::from(*id)).collect())
}

fn read_ids(r: &Record, key: u64) -> Result<Vec<Id>, SyncError> {
    r.list(key)?
        .iter()
        .map(|v| {
            v.as_bytes()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or(SyncError::Schema(SchemaError::Invalid(
                    "ids must be 32 bytes",
                )))
        })
        .collect()
}

/// A message of the `sync` service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// 1: `{0: 1, 1: label, 2: ranges}`.
    Reconcile {
        /// The set.
        label: Label,
        /// Ascending ranges covering every id.
        ranges: Vec<Range>,
    },
    /// 2: `{0: 2, 1: label, 2: ids}`; at most [`MAX_WANT`](crate::MAX_WANT) ids.
    Want {
        /// The set.
        label: Label,
        /// Ids requested.
        ids: Vec<Id>,
    },
    /// 3: `{0: 3, 1: label, 2: list of object bytes}`.
    Objects {
        /// The set.
        label: Label,
        /// Each object's bytes, as stored.
        objects: Vec<Vec<u8>>,
    },
    /// 4: `{0: 4, 1: label, 2: ids}`.
    Heads {
        /// The set.
        label: Label,
        /// The latest objects the sender holds.
        ids: Vec<Id>,
    },
}

impl Message {
    /// The record form.
    pub fn to_record(&self) -> Record {
        match self {
            Message::Reconcile { label, ranges } => {
                Record::new().with(0, 1u64).with(1, *label).with(
                    2,
                    Value::List(ranges.iter().map(|r| r.to_record().into()).collect()),
                )
            }
            Message::Want { label, ids } => Record::new()
                .with(0, 2u64)
                .with(1, *label)
                .with(2, id_list(ids)),
            Message::Objects { label, objects } => {
                Record::new().with(0, 3u64).with(1, *label).with(
                    2,
                    Value::List(objects.iter().map(|o| Value::from(o.clone())).collect()),
                )
            }
            Message::Heads { label, ids } => Record::new()
                .with(0, 4u64)
                .with(1, *label)
                .with(2, id_list(ids)),
        }
    }

    /// Reads the record form. Ranges of a reconcile message are checked:
    /// at least one, upper bounds strictly ascending, and only the last
    /// open-ended.
    pub fn from_record(r: &Record) -> Result<Message, SyncError> {
        let op = r.uint(0)?;
        let label = r.bytes_n::<32>(1)?;
        Ok(match op {
            1 => {
                let ranges = r
                    .record_list(2)?
                    .into_iter()
                    .map(Range::from_record)
                    .collect::<Result<Vec<_>, _>>()?;
                check_ranges(&ranges)?;
                Message::Reconcile { label, ranges }
            }
            2 => Message::Want {
                label,
                ids: read_ids(r, 2)?,
            },
            3 => Message::Objects {
                label,
                objects: r
                    .list(2)?
                    .iter()
                    .map(|v| {
                        v.as_bytes()
                            .map(<[u8]>::to_vec)
                            .ok_or(SchemaError::Invalid("objects must be bytes"))
                    })
                    .collect::<Result<_, _>>()?,
            },
            4 => Message::Heads {
                label,
                ids: read_ids(r, 2)?,
            },
            _ => return Err(SyncError::UnknownOp(op)),
        })
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Decodes a message.
    pub fn decode(bytes: &[u8]) -> Result<Message, SyncError> {
        Message::from_record(&Record::decode(bytes)?)
    }

    /// The label (or, for heads, the space id) the message is about.
    pub fn label(&self) -> &Label {
        match self {
            Message::Reconcile { label, .. }
            | Message::Want { label, .. }
            | Message::Objects { label, .. } => label,
            Message::Heads { label, .. } => label,
        }
    }
}

/// Checks that ranges cover every id: non-empty, strictly ascending upper
/// bounds, and exactly the last one open-ended.
pub(crate) fn check_ranges(ranges: &[Range]) -> Result<(), SyncError> {
    let Some((last, init)) = ranges.split_last() else {
        return Err(SyncError::BadRanges("no ranges"));
    };
    if last.upper.is_some() {
        return Err(SyncError::BadRanges("final range must be open-ended"));
    }
    let mut prev: Option<&Id> = None;
    for r in init {
        let Some(u) = &r.upper else {
            return Err(SyncError::BadRanges(
                "only the final range may be open-ended",
            ));
        };
        if prev.is_some_and(|p| p >= u) {
            return Err(SyncError::BadRanges("upper bounds must ascend"));
        }
        prev = Some(u);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let msgs = vec![
            Message::Reconcile {
                label: [1; 32],
                ranges: vec![
                    Range {
                        upper: Some([2; 32]),
                        mode: Mode::Skip,
                    },
                    Range {
                        upper: Some([3; 32]),
                        mode: Mode::Fingerprint([9; 16]),
                    },
                    Range {
                        upper: Some([4; 32]),
                        mode: Mode::List(vec![[3; 32], [3u8; 32].map(|x| x + 1)]),
                    },
                    Range {
                        upper: None,
                        mode: Mode::YouLack(vec![]),
                    },
                ],
            },
            Message::Want {
                label: [1; 32],
                ids: vec![[5; 32]],
            },
            Message::Objects {
                label: [1; 32],
                objects: vec![b"abc".to_vec(), vec![]],
            },
            Message::Heads {
                label: [7; 32],
                ids: vec![[8; 32], [9; 32]],
            },
        ];
        for m in msgs {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn rejects_bad_ranges() {
        let bad = |ranges: Vec<Range>| {
            Message::decode(
                &Message::Reconcile {
                    label: [0; 32],
                    ranges,
                }
                .encode(),
            )
            .is_err()
        };
        assert!(bad(vec![]));
        assert!(bad(vec![Range {
            upper: Some([1; 32]),
            mode: Mode::Skip
        }]));
        assert!(bad(vec![
            Range {
                upper: Some([2; 32]),
                mode: Mode::Skip
            },
            Range {
                upper: Some([1; 32]),
                mode: Mode::Skip
            },
            Range {
                upper: None,
                mode: Mode::Skip
            }
        ]));
        assert!(bad(vec![
            Range {
                upper: None,
                mode: Mode::Skip
            },
            Range {
                upper: None,
                mode: Mode::Skip
            }
        ]));
    }
}
