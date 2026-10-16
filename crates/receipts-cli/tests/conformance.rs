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
            let heights = Path::new(ROOT).join(v["heights"].as_str().unwrap_or("examples/regtest/heights.toml"));
            let regtest = v["regtest"].as_bool().unwrap().then_some(heights.as_path());
            let sources: Vec<(String, u32)> = v["source_txs"].as_array().map(|a| a.iter().map(|t| (t["raw_tx"].as_str().unwrap().to_string(), t["height"].as_u64().unwrap() as u32)).collect()).unwrap_or_default();
            let rep = receipts_chain::chain::verify_offline_with_sources(&r, &s("raw_tx"), v["height"].as_u64().unwrap() as u32, &sources, regtest).map_err(|e| e.to_string())?;
            Ok(serde_json::to_value(&rep).unwrap())
        }
        Some("incoming") => {
            let r = receipts_core::incoming::IncomingReceipt::from_text(&s("receipt")).ok_or("malformed")?;
            let rep = receipts_chain::chain::verify_incoming_offline(&r, &s("raw_tx"), v["height"].as_u64().unwrap() as u32, None).map_err(|e| e.to_string())?;
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
        if let (Ok(r), Some(srcs)) = (&got, v["expect"]["sources"].as_array()) {
            for (i, s) in srcs.iter().enumerate() {
                assert_eq!(r["sources"][i]["zatoshis"], s["zatoshis"], "{name}");
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

/// The real testnet ZIP 320 deposit, checked offline, plus the ways it must fail.
#[test]
fn tex_deposit_offline() {
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::{BranchId, NetworkType};
    let ex = |p: &str| std::fs::read_to_string(format!("{ROOT}/examples/testnet/{p}")).unwrap();
    let r = Receipt::from_text(ex("deposit-receipt.txt").trim()).unwrap();
    let tx = |p: &str| Transaction::read(&hex::decode(ex(p).trim()).unwrap()[..], BranchId::Nu6_3).unwrap();
    let (tx1, tx2) = (tx("deposit-tx1.hex"), tx("deposit-tx2.hex"));
    let msg = String::from_utf8_lossy(&r.unsigned.msg).into_owned();
    let d = receipts_core::deposit::check(&r, &msg, NetworkType::Test, &tx1, &tx2).unwrap();
    assert_eq!(d.deposit_zatoshis, 200_000);
    assert_eq!(d.tex_address, ex("merchant.tex").trim());
    // The spend proof for tx1 itself.
    let report = receipts_chain::chain::verify_offline(&r, &ex("deposit-tx1.hex"), 4_502_928, None).unwrap();
    assert!(report.valid && report.outputs.is_empty());
    // Swapped transactions, another network, or a claim naming another TEX: refused.
    assert!(receipts_core::deposit::check(&r, &msg, NetworkType::Test, &tx2, &tx1).is_err());
    assert!(receipts_core::deposit::check(&r, &msg, NetworkType::Main, &tx1, &tx2).is_err());
    let other = msg.replace(d.tex_address.as_str(), "textest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    assert!(receipts_core::deposit::check(&r, &other, NetworkType::Test, &tx1, &tx2).is_err());
}

/// Real testnet receipts with source proofs (examples/testnet/source), verified offline against
/// the payment and the source transaction; without the source transaction they are refused.
#[test]
fn source_of_funds_offline() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet/source/");
    let rd = |n: &str| std::fs::read_to_string(format!("{dir}{n}")).unwrap();
    for (name, value) in [("receipt-source-hidden.txt", None), ("receipt-source-value.txt", Some(12_500_000u64))] {
        let text = rd(name);
        let r = receipts_core::Receipt::from_text(text.trim()).unwrap();
        let rep = receipts_chain::chain::verify_offline_with_sources(&r, &rd("tx.hex"), 4_500_997, &[(rd("source-tx.hex"), 4_500_984)], None).unwrap();
        assert_eq!(rep.sources.len(), 1, "{name}");
        assert!(rep.sources[0].source_txid.starts_with("2a2bd721"), "{name}");
        assert_eq!(rep.sources[0].zatoshis, value, "{name}");
        let err = receipts_chain::chain::verify_offline(&r, &rd("tx.hex"), 4_500_997, None).err().expect("refused without the source").to_string();
        assert!(err.contains("not available"), "{name}: {err}");
        // A source mined after the payment is refused too.
        assert!(receipts_chain::chain::verify_offline_with_sources(&r, &rd("tx.hex"), 4_500_997, &[(rd("source-tx.hex"), 4_500_998)], None).is_err());
    }
}
