//! Runs the shared conformance vectors (conformance/vectors.json) through the Rust verifier.
//! The npm package runs the same file, so both must agree on every vector.

use receipts_core::{signin::SignIn, Receipt};
use serde_json::Value;
use std::path::Path;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn run(v: &Value) -> Result<Value, String> {
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    match v["type"].as_str() {
        Some("receipt") => {
            let r = Receipt::from_text(&s("receipt")).map_err(|e| e.to_string())?;
            let heights = Path::new(ROOT).join("examples/regtest/heights.toml");
            let regtest = v["regtest"].as_bool().unwrap().then_some(heights.as_path());
            let rep = receipts_chain::chain::verify_offline(&r, &s("raw_tx"), v["height"].as_u64().unwrap() as u32, regtest).map_err(|e| e.to_string())?;
            Ok(serde_json::to_value(&rep).unwrap())
        }
        Some("sign_in") => {
            let si = SignIn::from_text(&s("sign_in")).ok_or("malformed")?;
            let vk = vk();
            receipts_core::signin::verify_sign_in(vk, &si, si.coin_type, &s("domain"), &s("nonce")).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({ "network": if si.coin_type == receipts_core::COIN_TYPE_MAINNET { "mainnet" } else { "testnet" } }))
        }
        t => panic!("unknown vector type {t:?}"),
    }
}

fn vk() -> &'static orchard::circuit::VerifyingKey {
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    VK.get_or_init(receipts_core::verifying_key)
}

#[test]
fn conformance_vectors() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(format!("{ROOT}/conformance/vectors.json")).unwrap()).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() > 50);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let got = run(v);
        let want = v["expect"]["valid"].as_bool().unwrap();
        assert_eq!(got.is_ok(), want, "{name}: {got:?}");
        if let (Ok(r), Some(outs)) = (&got, v["expect"]["outputs"].as_array()) {
            for (i, o) in outs.iter().enumerate() {
                assert_eq!(r["outputs"][i]["zatoshis"], o["zatoshis"], "{name}");
                assert_eq!(r["outputs"][i]["memo"], o["memo"], "{name}");
            }
        }
        if let (Ok(r), Some(n)) = (&got, v["expect"]["network"].as_str()) {
            assert_eq!(r["network"], n, "{name}");
        }
    }
}

/// Decoders must never panic, whatever the input: random bytes, and random mutations of real
/// receipts and sign-ins (a small deterministic fuzz pass that runs in every `cargo test`).
#[test]
fn decoders_never_panic() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut x: u64 = 0x9e3779b97f4a7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let seeds: Vec<Vec<u8>> = [("examples/testnet/receipt.txt", "zrcpt1"), ("examples/testnet/sign-in.txt", "zsig1"), ("examples/testnet/batch.txt", "zrcptb1")]
        .iter()
        .map(|(p, pre)| {
            let t = std::fs::read_to_string(format!("{ROOT}/{p}")).unwrap();
            let i = t.find(pre).unwrap();
            let body: String = t[i + pre.len()..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
            URL_SAFE_NO_PAD.decode(body).unwrap()
        })
        .collect();
    for round in 0..20_000 {
        let mut b = if round % 5 == 0 {
            (0..(rnd() % 600) as usize).map(|_| rnd() as u8).collect::<Vec<u8>>()
        } else {
            seeds[round % seeds.len()].clone()
        };
        for _ in 0..1 + rnd() % 4 {
            if b.is_empty() {
                break;
            }
            let i = (rnd() as usize) % b.len();
            match rnd() % 3 {
                0 => b[i] ^= 1 << (rnd() % 8),
                1 => b.truncate(i),
                _ => b.insert(i, rnd() as u8),
            }
        }
        let text = URL_SAFE_NO_PAD.encode(&b);
        let _ = Receipt::from_text(&format!("zrcpt1{text}"));
        let _ = receipts_core::ReceiptBatch::from_text(&format!("zrcptb1{text}"));
        let _ = SignIn::from_text(&format!("zsig1{text}"));
    }
}
