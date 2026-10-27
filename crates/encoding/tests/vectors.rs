//! Generates and checks `vectors/encoding.json`.
//!
//! Run with `CARDINAL_WRITE_VECTORS=1` to rewrite the file after an
//! intentional change; otherwise the test fails if the file differs from
//! what this implementation produces.

use cardinal_encoding::{
    decode, DecodeError, ObjectSignature, Record, SignedObject, Value, MAX_DEPTH,
};
use serde_json::json;

fn vectors_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name)
}

fn check_or_write(name: &str, value: serde_json::Value) {
    let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
    let path = vectors_path(name);
    if std::env::var_os("CARDINAL_WRITE_VECTORS").is_some() {
        std::fs::write(&path, text).unwrap();
        return;
    }
    let existing = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with CARDINAL_WRITE_VECTORS=1", path.display()));
    assert!(
        existing == text,
        "{} is out of date with the implementation",
        path.display()
    );
}

fn category(e: &DecodeError) -> &'static str {
    use DecodeError::*;
    match e {
        UnexpectedEnd { .. } => "unexpected_end",
        NonMinimalVarint { .. } => "non_minimal_varint",
        VarintTooLong { .. } => "varint_too_long",
        ReservedType { .. } => "reserved_type",
        LengthExceedsInput { .. } => "length_exceeds_input",
        InvalidUtf8 { .. } => "invalid_utf8",
        UnsortedKeys { .. } => "unsorted_keys",
        DuplicateKey { .. } => "duplicate_key",
        TooDeep { .. } => "too_deep",
        TrailingBytes { .. } => "trailing_bytes",
        NotARecord { .. } => "not_a_record",
    }
}

fn nested_lists(depth: usize) -> Value {
    let mut v = Value::from(0u32);
    for _ in 0..depth {
        v = Value::List(vec![v]);
    }
    v
}

#[test]
fn encoding_vectors() {
    let valid: Vec<(&str, Value)> = vec![
        ("uint 0", Value::from(0u32)),
        ("uint 1", Value::from(1u32)),
        ("uint 15 (largest one-byte)", Value::from(15u32)),
        ("uint 16", Value::from(16u32)),
        ("uint 1000", Value::from(1000u32)),
        ("uint 2^32", Value::from(1u64 << 32)),
        ("uint max 2^60-1", Value::from((1u64 << 60) - 1)),
        ("neg -1", Value::from(-1i32)),
        ("neg -16", Value::from(-16i32)),
        ("neg -17", Value::from(-17i32)),
        ("neg min -2^60", Value::from(-(1i64 << 60))),
        ("bool true", Value::from(true)),
        ("empty bytes", Value::from(Vec::<u8>::new())),
        ("bytes", Value::from(vec![0x00, 0x01, 0xfe, 0xff])),
        ("bytes 32", Value::from([0xabu8; 32])),
        ("empty text", Value::from("")),
        ("text", Value::from("Ana")),
        (
            "text escapes",
            Value::from("line\n\"quoted\" \\ tab\t \u{1}"),
        ),
        ("text non-ascii", Value::from("café 🐦")),
        ("empty list", Value::List(vec![])),
        (
            "list",
            Value::list([
                Value::from(1u32),
                Value::from("two"),
                Value::from(vec![3u8]),
            ]),
        ),
        ("empty record", Value::Record(Record::new())),
        (
            "spec example",
            Record::new()
                .with(0, 6u32)
                .with(1, vec![0x0a, 0x0b])
                .with(3, "Ana")
                .into(),
        ),
        (
            "record with large and unknown keys",
            Record::new()
                .with(0, 4u32)
                .with(127, "a")
                .with(128, "b")
                .with(1 << 40, -3i32)
                .into(),
        ),
        (
            "nested",
            Record::new()
                .with(0, Value::from([1u8; 32]))
                .with(
                    1,
                    Value::list([Value::from(Record::new().with(1, Value::List(vec![])))]),
                )
                .into(),
        ),
        ("depth 32 (maximum)", nested_lists(MAX_DEPTH)),
        ("bytes 200 (two-byte header)", Value::from(vec![7u8; 200])),
    ];

    // A signed object with fixed (not cryptographically valid) signatures,
    // to pin the structure; real signatures are in ed25519.json.
    let mut signed = SignedObject::new(Record::new().with(0, 2u32).with(1, "body"));
    signed.add_signature(ObjectSignature::new([2; 32], [0x22; 64]));
    signed.add_signature(ObjectSignature::new([1; 32], [0x11; 64]));

    let mut valid_json = Vec::new();
    for (name, v) in &valid {
        let bytes = v.encode();
        assert_eq!(&decode(&bytes).unwrap(), v);
        valid_json.push(json!({ "name": name, "text": v.to_string(), "hex": hex::encode(&bytes) }));
    }
    let signed_bytes = signed.encode();
    valid_json.push(json!({
        "name": "signed object structure",
        "text": decode(&signed_bytes).unwrap().to_string(),
        "hex": hex::encode(&signed_bytes),
        "id": hex::encode(signed.id()),
        "signing_message": hex::encode(signed.signing_message()),
    }));

    let mut too_deep = nested_lists(MAX_DEPTH + 1).encode();
    let invalid: Vec<(&str, Vec<u8>)> = vec![
        ("empty input", vec![]),
        ("reserved type 6", vec![0x06]),
        ("reserved type 7", vec![0x07]),
        ("reserved type inside list", vec![0x0c, 0x0e]),
        ("non-minimal header", vec![0x80, 0x00]),
        ("non-minimal header 3 bytes", vec![0x88, 0x80, 0x00]),
        ("non-minimal record key", vec![0x0d, 0x81, 0x00, 0x00]),
        (
            "varint longer than 9 bytes",
            vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        ),
        ("truncated varint", vec![0x80]),
        ("trailing bytes", vec![0x00, 0x00]),
        ("bytes length past end", vec![0x12, 0x0a]),
        ("text invalid utf-8", vec![0x0b, 0xff]),
        ("text overlong utf-8", vec![0x13, 0xc0, 0x80]),
        ("text surrogate", vec![0x1b, 0xed, 0xa0, 0x80]),
        ("record keys unsorted", vec![0x15, 0x01, 0x00, 0x00, 0x00]),
        ("record keys duplicate", vec![0x15, 0x01, 0x00, 0x01, 0x00]),
        ("record missing value", vec![0x0d, 0x00]),
        ("list count past end", vec![0x14, 0x00]),
        (
            "huge list count",
            vec![0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f],
        ),
        ("depth 33", std::mem::take(&mut too_deep)),
    ];
    let mut invalid_json = Vec::new();
    for (name, bytes) in &invalid {
        let err = decode(bytes).expect_err(name);
        invalid_json
            .push(json!({ "name": name, "hex": hex::encode(bytes), "error": category(&err) }));
    }

    check_or_write(
        "encoding.json",
        json!({
            "description": "Cardinal canonical encoding (spec/encoding.md). 'valid' entries: decoding 'hex' MUST succeed, re-encoding MUST give the same bytes, and the canonical text rendering is 'text'. 'invalid' entries MUST be rejected when the input is one value; 'error' names the rule broken (advisory).",
            "valid": valid_json,
            "invalid": invalid_json,
        }),
    );
}
