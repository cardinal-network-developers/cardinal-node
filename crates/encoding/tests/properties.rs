//! Property tests: round trips, and every accepted encoding is canonical.

use cardinal_encoding::{decode, decode_prefix, Int, Record, Value, MAX_DEPTH};
use proptest::prelude::*;

fn arb_int() -> impl Strategy<Value = Int> {
    prop_oneof![
        (-300i64..300).prop_map(|v| Int::new(v).unwrap()),
        (Int::MIN.get()..=Int::MAX.get()).prop_map(|v| Int::new(v).unwrap()),
        Just(Int::MIN),
        Just(Int::MAX),
    ]
}

fn arb_key() -> impl Strategy<Value = u64> {
    prop_oneof![0u64..20, 0u64..100_000, 0u64..=(1u64 << 63) - 1]
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        arb_int().prop_map(Value::Int),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,20}".prop_map(Value::Text),
    ];
    leaf.prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::List),
            proptest::collection::vec((arb_key(), inner), 0..8)
                .prop_map(|fields| Value::Record(fields.into_iter().collect::<Record>())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn round_trip(v in arb_value()) {
        let bytes = v.encode();
        prop_assert_eq!(bytes.len(), v.encoded_len());
        prop_assert_eq!(decode(&bytes).unwrap(), v);
    }

    #[test]
    fn concatenated_values_decode_by_prefix(a in arb_value(), b in arb_value()) {
        let mut bytes = a.encode();
        let n = bytes.len();
        bytes.extend(b.encode());
        let (da, used) = decode_prefix(&bytes).unwrap();
        prop_assert_eq!(used, n);
        prop_assert_eq!(da, a);
        prop_assert_eq!(decode(&bytes[n..]).unwrap(), b);
        // The concatenation is not one value.
        prop_assert!(decode(&bytes).is_err());
    }

    #[test]
    fn random_bytes_accepted_only_if_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(v) = decode(&bytes) {
            prop_assert_eq!(v.encode(), bytes);
            prop_assert!(v.depth() <= MAX_DEPTH);
        }
    }

    #[test]
    fn mutated_encodings_accepted_only_if_canonical(
        v in arb_value(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..3), 1..4),
    ) {
        let mut bytes = v.encode();
        for (idx, byte, op) in edits {
            match op {
                0 if !bytes.is_empty() => { let i = idx.index(bytes.len()); bytes[i] = byte; }
                1 => { let i = idx.index(bytes.len() + 1); bytes.insert(i, byte); }
                _ if !bytes.is_empty() => { let i = idx.index(bytes.len()); bytes.remove(i); }
                _ => {}
            }
        }
        if let Ok(d) = decode(&bytes) {
            prop_assert_eq!(d.encode(), bytes);
        }
    }

    #[test]
    fn record_field_order_is_irrelevant(fields in proptest::collection::vec((arb_key(), arb_int()), 0..12)) {
        let forward: Record = fields.iter().map(|(k, v)| (*k, *v)).collect();
        // Insert in reverse order, letting the first occurrence win as above
        // (FromIterator lets later duplicates win, so dedupe first).
        let mut dedup = std::collections::BTreeMap::new();
        for (k, v) in &fields { dedup.insert(*k, *v); }
        let mut reverse = Record::new();
        for (k, v) in dedup.iter().rev() { reverse.insert(*k, *v); }
        prop_assert_eq!(forward.encode(), reverse.encode());
        let bytes = forward.encode();
        // Keys strictly increase in the encoding.
        let back = Record::decode(&bytes).unwrap();
        let keys: Vec<u64> = back.keys().collect();
        prop_assert!(keys.windows(2).all(|w| w[0] < w[1]));
    }
}
