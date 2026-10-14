//! Payment-link preflight: lints a ZIP-321 `zcash:` URI before you print it on an invoice or a
//! QR code, so customers don't pay a wrong network, a memo-less exchange address, or an address
//! no receipt can ever prove.

use serde_json::{json, Value};
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::{
    consensus::NetworkType,
    memo::{Memo, MemoBytes},
    PoolType, ShieldedPool,
};
use zip321::TransactionRequest;

/// QR versions above this are hard for phone cameras at receipt-printer sizes.
pub const QR_COMFORT_VERSION: i16 = 20;

struct Findings(Vec<Value>);

impl Findings {
    fn add(&mut self, level: &str, code: &str, payment: Option<usize>, message: String) {
        self.0.push(json!({ "level": level, "code": code, "payment": payment, "message": message }));
    }
}

fn network_name(n: NetworkType) -> &'static str {
    match n {
        NetworkType::Main => "mainnet",
        NetworkType::Test => "testnet",
        NetworkType::Regtest => "regtest",
    }
}

/// Address kind, network and (for unified addresses) receiver types, from the encoding.
fn describe(addr: &str) -> (String, Option<NetworkType>, Vec<&'static str>) {
    if let Ok((net, _, ua)) = unified::Address::decode(addr) {
        let receivers = ua
            .items()
            .iter()
            .map(|i| match i {
                unified::Receiver::Orchard(_) => "orchard",
                unified::Receiver::Sapling(_) => "sapling",
                unified::Receiver::P2pkh(_) => "p2pkh",
                unified::Receiver::P2sh(_) => "p2sh",
                unified::Receiver::Unknown { .. } => "unknown",
            })
            .collect();
        return ("unified".into(), Some(net), receivers);
    }
    let pre = |p: &[&str]| p.iter().any(|x| addr.starts_with(x));
    if pre(&["tex1"]) {
        ("tex".into(), Some(NetworkType::Main), vec!["p2pkh"])
    } else if pre(&["textest1"]) {
        ("tex".into(), Some(NetworkType::Test), vec!["p2pkh"])
    } else if pre(&["zs1"]) {
        ("sapling".into(), Some(NetworkType::Main), vec!["sapling"])
    } else if pre(&["ztestsapling1"]) {
        ("sapling".into(), Some(NetworkType::Test), vec!["sapling"])
    } else if pre(&["zregtestsapling1"]) {
        ("sapling".into(), Some(NetworkType::Regtest), vec!["sapling"])
    } else if pre(&["t1", "t3"]) {
        ("transparent".into(), Some(NetworkType::Main), vec![if addr.starts_with("t3") { "p2sh" } else { "p2pkh" }])
    } else if pre(&["tm", "t2"]) {
        ("transparent".into(), Some(NetworkType::Test), vec![if addr.starts_with("t2") { "p2sh" } else { "p2pkh" }])
    } else {
        ("unknown".into(), None, vec![])
    }
}

/// Checks `uri`. `expected_network` ("mainnet", "testnet", "regtest") makes a network mismatch
/// an error. Returns `{ ok, uri_length, payments, total_zatoshis, qr, findings }`.
pub fn check_payment_uri(uri: &str, expected_network: Option<&str>) -> Value {
    let mut f = Findings(vec![]);
    let uri = uri.trim();
    if uri.len() >= 6 && uri[..6].eq_ignore_ascii_case("zcash:") && !uri.starts_with("zcash:") {
        f.add("warning", "scheme_case", None, "the scheme should be lowercase `zcash:`; some wallets reject other cases".into());
    }
    let normalized = if uri.len() >= 6 && uri[..6].eq_ignore_ascii_case("zcash:") { format!("zcash:{}", &uri[6..]) } else { uri.to_string() };
    let req = match TransactionRequest::from_uri(&normalized) {
        Ok(r) => r,
        Err(e) => {
            f.add("error", "invalid_uri", None, format!("not a valid ZIP-321 payment URI: {e}"));
            return json!({ "ok": false, "uri_length": uri.len(), "payments": [], "findings": f.0 });
        }
    };
    let payments = req.payments();
    if payments.len() > 1 {
        f.add("warning", "multiple_payments", None, format!("{} payments in one URI; several wallets only support one", payments.len()));
    }
    let mut out = Vec::new();
    let mut networks = std::collections::BTreeSet::new();
    for (i, p) in payments {
        let i = *i;
        let addr = p.recipient_address().encode();
        let (kind, net, receivers) = describe(&addr);
        if let Some(n) = net {
            networks.insert(network_name(n));
            if let Some(want) = expected_network {
                if network_name(n) != want && !(want == "regtest" && n == NetworkType::Test) {
                    f.add("error", "network_mismatch", Some(i), format!("this is a {} address, but you expect {want}", network_name(n)));
                }
            }
        }
        let provable = p.recipient_address().can_receive_as(PoolType::Shielded(ShieldedPool::Orchard));
        match kind.as_str() {
            "tex" => f.add("warning", "tex_address", Some(i), "a TEX (exchange) address: it must be paid from transparent funds, shows the payment on chain, and no receipt can prove it. Ask the payer to use the exchange's own flow".into()),
            "transparent" => f.add("warning", "transparent_recipient", Some(i), "a transparent address: amount and recipient are public on chain, and there is no memo".into()),
            "sapling" => f.add("warning", "sapling_only", Some(i), "a Sapling-only address: payable, but Receipts can only prove payments to Orchard/Ironwood receivers. Use a unified address".into()),
            "unified" if !provable => f.add("warning", "no_orchard_receiver", Some(i), "this unified address has no Orchard receiver, so a receipt cannot prove payments to it".into()),
            _ => {}
        }
        if receivers.contains(&"p2pkh") && kind == "unified" {
            f.add("info", "transparent_receiver", Some(i), "the unified address also carries a transparent receiver; good wallets will still pay the shielded one".into());
        }
        match p.amount() {
            None => f.add("warning", "amount_missing", Some(i), "no amount: the payer types it, and typos happen. Set `amount=`".into()),
            Some(a) if u64::from(a) == 0 => f.add("warning", "zero_amount", Some(i), "the amount is zero".into()),
            _ => {}
        }
        let memo_text = p.memo().map(|m: &MemoBytes| match Memo::try_from(m.clone()) {
            Ok(Memo::Text(t)) => Some(t.to_string()),
            _ => None,
        });
        if p.memo().is_none() && provable {
            f.add("info", "memo_missing", Some(i), "no memo: adding an order number lets you match the payment without asking the customer".into());
        }
        if let Some(l) = p.label() {
            if l.chars().count() > 64 {
                f.add("warning", "long_label", Some(i), "the label is over 64 characters; wallets may truncate it".into());
            }
        }
        for (k, _) in p.other_params() {
            if k.starts_with("req-") {
                f.add("error", "required_param_unsupported", Some(i), format!("`{k}` is a required parameter; ZIP-321 wallets must refuse URIs with requirements they don't know"));
            } else {
                f.add("info", "unknown_param", Some(i), format!("`{k}` is not a ZIP-321 parameter; wallets ignore it"));
            }
        }
        out.push(json!({
            "index": i,
            "address": addr,
            "address_kind": kind,
            "network": net.map(network_name),
            "receivers": receivers,
            "amount_zatoshis": p.amount().map(u64::from),
            "memo": memo_text.flatten(),
            "label": p.label(),
            "message": p.message(),
            "receipt_provable": provable,
        }));
    }
    if networks.len() > 1 {
        f.add("error", "mixed_networks", None, "payments to more than one network in one URI".into());
    }
    let total = req.total().ok().flatten().map(u64::from);
    let qr = match qrcode::QrCode::with_error_correction_level(normalized.as_bytes(), qrcode::EcLevel::M) {
        Ok(code) => {
            let v = match code.version() {
                qrcode::Version::Normal(n) => n,
                qrcode::Version::Micro(n) => n,
            };
            if v > QR_COMFORT_VERSION {
                f.add("warning", "dense_qr", None, format!("the QR code needs version {v} ({}×{} modules); phones struggle above {QR_COMFORT_VERSION}. Shorten the memo, label or message", code.width(), code.width()));
            }
            json!({ "version": v, "modules": code.width(), "error_correction": "M" })
        }
        Err(_) => {
            f.add("error", "qr_too_long", None, "too long for any QR code".into());
            Value::Null
        }
    };
    let ok = !f.0.iter().any(|x| x["level"] == "error");
    json!({ "ok": ok, "uri_length": uri.len(), "payments": out, "total_zatoshis": total, "qr": qr, "findings": f.0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    const UA: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

    fn codes(v: &Value) -> Vec<String> {
        v["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn clean_link() {
        let v = check_payment_uri(&format!("zcash:{UA}?amount=0.01&memo=SW52b2ljZSA0Mg"), Some("testnet"));
        assert_eq!(v["ok"], true, "{v}");
        assert!(codes(&v).is_empty(), "{v}");
        assert_eq!(v["payments"][0]["memo"], "Invoice 42");
        assert_eq!(v["payments"][0]["receipt_provable"], true);
        assert_eq!(v["total_zatoshis"], 1_000_000);
    }

    #[test]
    fn problems_are_found() {
        let v = check_payment_uri(&format!("zcash:{UA}?amount=0.01"), Some("mainnet"));
        assert_eq!(v["ok"], false);
        assert!(codes(&v).contains(&"network_mismatch".into()));
        assert!(codes(&v).contains(&"memo_missing".into()));
        let v = check_payment_uri("zcash:tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU?amount=1", None);
        assert!(codes(&v).contains(&"transparent_recipient".into()), "{v}");
        assert_eq!(v["payments"][0]["receipt_provable"], false);
        let v = check_payment_uri(&format!("zcash:{UA}?req-foo=1"), None);
        assert!(codes(&v).contains(&"required_param_unsupported".into()) || codes(&v).contains(&"invalid_uri".into()), "{v}");
        assert_eq!(v["ok"], false);
        assert!(codes(&check_payment_uri(&format!("zcash:{UA}"), None)).contains(&"amount_missing".into()));
        assert_eq!(check_payment_uri("bitcoin:abc", None)["ok"], false);
        let long = "A".repeat(1200);
        let v = check_payment_uri(&format!("zcash:{UA}?amount=1&message={long}"), None);
        assert!(codes(&v).contains(&"dense_qr".into()), "{v}");
    }
}
