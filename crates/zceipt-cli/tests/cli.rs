//! The `zceipt` binary end to end, offline: the demo, offline verification of every committed
//! example, inspect, check-link, privacy-lint and pay's dry run.

use std::process::Command;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn zceipt(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zceipt")).args(args).current_dir(ROOT).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

#[test]
fn demo_runs_every_step() {
    // The default demo: the real receipt and the edited copy, nothing else.
    let (ok, out) = zceipt(&["demo"]);
    assert!(ok && out.contains("Halo 2 spend proof and signature valid") && out.contains("refused") && !out.contains("[sandbox]"), "{out}");
    let (ok, out) = zceipt(&["demo", "--shop", "--no-wait"]);
    assert!(ok, "{out}");
    for want in ["request.fulfilled ✓", "request.final ✓", "refund.succeeded ✓", "anyone can check it: valid true", "Halo 2 spend proof and signature valid"]
    {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
}

#[test]
fn offline_verification_of_every_example() {
    let h = std::fs::read_to_string(format!("{ROOT}/examples/regtest-crosspool/height")).unwrap();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec![
                "verify",
                "@examples/testnet/receipt.txt",
                "--raw-tx",
                "examples/testnet/tx.hex",
                "--height",
                "4500997",
                "--expect-address",
                "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa",
            ],
            "Invoice 42",
        ),
        (
            vec![
                "verify",
                "@examples/regtest/receipt.txt",
                "--regtest",
                "examples/regtest/heights.toml",
                "--raw-tx",
                "examples/regtest/tx.hex",
                "--height",
                "222",
            ],
            "pool      Ironwood",
        ),
        (
            vec![
                "verify",
                "@examples/regtest-orchard/receipt.txt",
                "--regtest",
                "examples/regtest-orchard/heights.toml",
                "--raw-tx",
                "examples/regtest-orchard/tx.hex",
                "--height",
                "212",
            ],
            "pool      Orchard",
        ),
        (
            vec![
                "verify",
                "@examples/regtest-crosspool/receipt.txt",
                "--regtest",
                "examples/regtest-crosspool/heights.toml",
                "--raw-tx",
                "examples/regtest-crosspool/tx.hex",
                "--height",
                h.trim(),
            ],
            "Orchard to Ironwood",
        ),
        (
            vec![
                "verify",
                "@examples/testnet/deposit-receipt.txt",
                "--raw-tx",
                "examples/testnet/deposit-tx1.hex",
                "--height",
                "4502928",
                "--second-raw-tx",
                "examples/testnet/deposit-tx2.hex",
            ],
            "EXCHANGE DEPOSIT",
        ),
    ];
    for (args, want) in cases {
        let (ok, out) = zceipt(&args);
        assert!(ok && out.contains(want), "{args:?}:\n{out}");
    }
    // JSON output, and failures exit non-zero.
    let (ok, out) = zceipt(&["verify", "@examples/testnet/receipt.txt", "--raw-tx", "examples/testnet/tx.hex", "--height", "4500997", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
    assert!(ok && v["valid"] == true, "{out}");
    let (ok, _) = zceipt(&["verify", "@examples/testnet/receipt.txt", "--raw-tx", "examples/regtest/tx.hex", "--height", "222"]);
    assert!(!ok, "a receipt checked against another transaction must fail");
    let (ok, out) = zceipt(&["verify", "@examples/testnet/deposit-receipt.txt", "--raw-tx", "examples/testnet/deposit-tx1.hex", "--height", "4502928"]);
    assert!(!ok && out.contains("--second-raw-tx"), "{out}");
}

#[test]
fn inspect_check_link_and_privacy_lint() {
    let (ok, out) = zceipt(&["inspect", "@examples/testnet/receipt.txt"]);
    assert!(ok && out.contains("571de6e4"), "{out}");
    let (ok, out) = zceipt(&[
        "check-link",
        "zcash:utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa?amount=0.01",
        "--network",
        "testnet",
    ]);
    assert!(ok && out.contains("provable with a receipt"), "{out}");
    let (ok, _) = zceipt(&[
        "check-link",
        "zcash:utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa?amount=0.01",
        "--network",
        "mainnet",
    ]);
    assert!(!ok);
    // A planted viewing key (built at runtime so this file stays clean) is found and redacted.
    let dir = tempdir();
    let key = format!("{}{}", "uview1", "q".repeat(70));
    std::fs::write(dir.join("app.log"), format!("user pasted {key}\n")).unwrap();
    let (ok, out) = zceipt(&["privacy-lint", dir.to_str().unwrap()]);
    assert!(!ok && out.contains("app.log:1") && !out.contains(&key), "{out}");
}

#[test]
fn pay_dry_run_shows_what_it_would_pay() {
    let dir = tempdir();
    std::fs::write(dir.join("keys.toml"), "network = \"test\"\n").unwrap();
    let to = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";
    let link = format!("https://shop.example/?request=0011223344556677&to={to}&min=250000");
    let w = dir.to_str().unwrap();
    let (ok, out) = zceipt(&["pay", &link, "-w", w, "-i", "/nonexistent.age", "--dry-run"]);
    assert!(ok && out.contains("0.00250000 ZEC") && out.contains(to) && out.contains("shop.example"), "{out}");
    // A transparent payee can't be proven: refused before anything is sent.
    let (ok, out) =
        zceipt(&["pay", "https://shop.example/?request=0011223344556677&to=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&min=1", "-w", w, "-i", "/x", "--dry-run"]);
    assert!(!ok && out.contains("can't be proven"), "{out}");
}

#[cfg(unix)]
#[test]
fn secret_key_files_are_private_from_the_first_byte() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempdir();
    let key = d.join("shop.key");
    let (ok, out) = zceipt(&["verifier-key", "--out", key.to_str().unwrap()]);
    assert!(ok, "{out}");
    assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    // Never overwritten.
    let (ok, _) = zceipt(&["verifier-key", "--out", key.to_str().unwrap()]);
    assert!(!ok);
}

fn tempdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "zceipt-cli-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A flag the chosen kind of artifact doesn't implement is an error, never silently skipped.
#[test]
fn verify_refuses_flags_the_artifact_kind_ignores() {
    let base =
        ["verify", "@examples/testnet/proofs/listclaim.txt", "--list", "examples/testnet/proofs/list.txt", "--domain", "list-airdrop", "--min", "0.00000001"];
    let (ok, out) = zceipt(&base);
    assert!(ok && out.contains("VALID list claim"), "{out}");
    let merchant = std::fs::read_to_string(format!("{ROOT}/examples/testnet/merchant.ua")).unwrap();
    for extra in [vec!["--expect-address", merchant.trim()], vec!["--memo-contains", "x"]] {
        let (ok, out) = zceipt(&[&base[..], &extra[..]].concat());
        assert!(!ok && out.contains("doesn't apply"), "{extra:?}: {out}");
    }
    // A challenge the claim doesn't sign fails instead of being skipped.
    let (ok, out) = zceipt(&[&base[..], &["--challenge", "deadbeef"][..]].concat());
    assert!(!ok && out.contains("doesn't sign challenge"), "{out}");
}

/// A proof of income is no answer to a receipt check.
#[test]
fn verify_refuses_expect_address_on_a_proof_of_income() {
    let merchant = std::fs::read_to_string(format!("{ROOT}/examples/testnet/merchant.ua")).unwrap();
    let (ok, out) = zceipt(&["verify", "@examples/testnet/proofs/income.txt", "--expect-address", merchant.trim()]);
    assert!(!ok && out.contains("doesn't apply"), "{out}");
    // Flags of other kinds are refused too, before anything is fetched.
    let (ok, out) = zceipt(&["verify", "@examples/testnet/batch-same-payer.txt", "--cross-check", "https://example.invalid:443"]);
    assert!(!ok && out.contains("doesn't apply"), "{out}");
    let (ok, out) = zceipt(&["verify", "@examples/testnet/receipt.txt", "--min-payments", "2"]);
    assert!(!ok && out.contains("doesn't apply"), "{out}");
}

const SAPLING_RECEIPT: &str = "@examples/testnet-sapling/receipt.txt";
const SAPLING_PAYEE: &str = "ztestsapling1v99fx63vu4xeewvfuhvpcmde5rakr858h49qaq75y6df4sr0m8wv0t65eaq32fsw9ma4c5pnc58";
/// The Sapling example's transaction, so it verifies offline; `-s 127.0.0.1:1` makes any fetch fail.
const SAPLING_OFFLINE: [&str; 8] =
    ["verify", SAPLING_RECEIPT, "--raw-tx", "crates/zceipt-cli/tests/fixtures/testnet-sapling-tx.hex", "--height", "4552325", "-s", "127.0.0.1:1"];

/// A Sapling receipt (`zip311z1…`) honours the one-payment checks: the right values pass and
/// each wrong one fails, offline.
#[test]
fn verify_sapling_receipt_checks_the_payment_flags() {
    let run = |extra: &[&str]| zceipt(&[&SAPLING_OFFLINE[..], extra].concat());
    let (ok, out) = run(&["--expect-address", SAPLING_PAYEE, "--min", "0.005", "--memo-contains", "invoice 311", "--network", "test"]);
    assert!(ok && out.starts_with("VERIFIED"), "{out}");
    assert!(out.contains("paid 0.00500000 TAZ to the expected address"), "{out}");
    let (ok, out) = run(&["--json"]);
    assert!(ok && out.contains("\"fetched_by\": \"offline\""), "{out}");
    // The merchant's unified address carries the Sapling receiver that was paid; the sender's doesn't.
    let merchant = std::fs::read_to_string(format!("{ROOT}/examples/testnet/merchant.ua")).unwrap();
    let (ok, out) = run(&["--expect-address", merchant.trim()]);
    assert!(ok && out.contains("paid 0.00500000 TAZ to the expected address"), "{out}");
    let sender = std::fs::read_to_string(format!("{ROOT}/examples/testnet/sender.ua")).unwrap();
    let mainnet = std::fs::read_to_string(format!("{ROOT}/examples/testnet/merchant-mainnet.ua")).unwrap();
    // The payee's receiver encoded for mainnet; the merchant's mainnet address has no Sapling receiver at all.
    let wrong: [(&[&str], &str); 8] = [
        (
            &["--expect-address", "zs1v99fx63vu4xeewvfuhvpcmde5rakr858h49qaq75y6df4sr0m8wv0t65eaq32fsw9ma4cukpmnn"],
            "is a mainnet address, but the payment is on testnet",
        ),
        (&["--challenge", "0123456789ab"], "signs no challenge"),
        (&["--min", "1", "--expect-address", SAPLING_PAYEE], "less than"),
        (&["--min", "1"], "give the address too"),
        (&["--memo-contains", "nope"], "memo contains"),
        (&["--expect-address", sender.trim()], "no disclosed output pays"),
        (&["--expect-address", mainnet.trim()], "no Sapling receiver"),
        (&["--network", "main"], "main"),
    ];
    for (extra, want) in wrong {
        let (ok, out) = run(extra);
        assert!(!ok && out.contains(want), "{extra:?}: {out}");
    }
    // A raw transaction that isn't the receipt's is refused, offline.
    let (ok, out) = zceipt(&["verify", SAPLING_RECEIPT, "--raw-tx", "examples/testnet/tx.hex", "--height", "4500997", "-s", "127.0.0.1:1"]);
    assert!(!ok && out.contains("different transaction"), "{out}");
}

/// A flag a Sapling receipt doesn't implement is refused before anything is fetched, and a
/// Sapling receipt pasted after another receipt can't take the Sapling path past the count.
#[test]
fn verify_sapling_receipt_refuses_flags_it_ignores() {
    let (ok, out) = zceipt(&SAPLING_OFFLINE);
    assert!(ok, "{out}");
    let refused: [&[&str]; 9] = [
        &["--list", "examples/testnet/proofs/list.txt"],
        &["--key-set", "examples/testnet/merchant.ua"],
        &["--policy-commitment", "examples/testnet/merchant.ua"],
        &["--cross-check", "example.invalid:443"],
        &["--domain", "airdrop"],
        &["--min-payments", "2"],
        &["--verifier-key", "examples/testnet/merchant.ua"],
        &["--screened-set", "examples/testnet/merchant.ua", "--screened-proof", "examples/testnet/merchant.ua"],
        &["--second-raw-tx", "examples/testnet/tx.hex"],
    ];
    for extra in refused {
        let (ok, out) = zceipt(&[&SAPLING_OFFLINE[..], extra].concat());
        assert!(!ok && out.contains("doesn't apply to a Sapling receipt"), "{extra:?}: {out}");
    }
    let dir = tempdir();
    let both = dir.join("both.txt");
    let orchard = std::fs::read_to_string(format!("{ROOT}/examples/testnet/receipt.txt")).unwrap();
    let sapling = std::fs::read_to_string(format!("{ROOT}/examples/testnet-sapling/receipt.txt")).unwrap();
    std::fs::write(&both, format!("{}\n{}", orchard.trim(), sapling.trim())).unwrap();
    let (ok, out) = zceipt(&["verify", &format!("@{}", both.display()), "-s", "127.0.0.1:1"]);
    assert!(!ok && out.contains("more than one receipt"), "{out}");
}

/// `create` and `sign` without a key source name every alternative, not just the wallet's flags.
#[test]
fn create_and_sign_name_their_key_sources() {
    let (ok, out) = zceipt(&["create", "--txid", "00"]);
    assert!(!ok && out.contains("--seed-stdin") && out.contains("--ufvk") && out.contains("--wallet"), "{out}");
    let (ok, out) = zceipt(&["sign", "r.txt"]);
    assert!(!ok && out.contains("--seed-stdin") && out.contains("--session") && out.contains("--wallet"), "{out}");
    for cmd in ["create", "sign"] {
        let (ok, out) = zceipt(&[cmd, "--help"]);
        assert!(ok && out.contains("Either a zcash-devtool wallet (-w, -i), a seed phrase (--seed-stdin)"), "{cmd}: {out}");
    }
    // A wallet needs its identity (or, for create, --unsigned).
    let (ok, out) = zceipt(&["create", "--txid", "00", "-w", "nowhere"]);
    assert!(!ok && out.contains("--identity") && out.contains("--unsigned"), "{out}");
    let (ok, out) = zceipt(&["sign", "r.txt", "-w", "nowhere"]);
    assert!(!ok && out.contains("--identity"), "{out}");
}

/// The verdict is the first line; a tampered receipt is NOT VALID with the reason; junk is named.
#[test]
fn verify_output_leads_with_the_verdict() {
    let (ok, out) = zceipt(&["verify", "@examples/testnet/receipt.txt", "--raw-tx", "examples/testnet/tx.hex", "--height", "4500997", "--json"]);
    assert!(ok && out.contains("\"fetched_by\": \"offline\""), "{out}");
    let (ok, out) = zceipt(&["verify", "@examples/testnet/receipt-edited.txt", "--raw-tx", "examples/testnet/tx.hex", "--height", "4500997"]);
    assert!(!ok, "{out}");
    assert!(
        out.starts_with("NOT VALID: the signature for action 0 is invalid (the receipt was changed after it was made, or not made by the wallet that paid)"),
        "{out}"
    );
    let (ok, out) = zceipt(&["verify", "zip311r1a"]);
    assert!(!ok && out.contains("Error: this isn't a receipt (invalid base64 after the zip311… prefix)"), "{out}");
}

/// `demo -m --out` writes the receipt and names the file; without it the hint says what to do
/// with the line; the next steps don't point into a checkout that isn't there.
#[test]
fn demo_hints_work_outside_a_checkout() {
    let dir = tempdir();
    let out_file = dir.join("r.txt");
    let (ok, out) = zceipt(&["demo", "-m", "hello", "--out", out_file.to_str().unwrap()]);
    assert!(ok && out.contains(&format!("zceipt verify @{}", out_file.display())), "{out}");
    let written = std::fs::read_to_string(&out_file).unwrap();
    assert!(written.starts_with("zip311r1") && written.contains("&h="), "{written}");
    let (ok, out) = zceipt(&["demo", "-m", "hello"]);
    assert!(ok && out.contains("Save the line above to a file and run: zceipt verify @file") && out.contains("block hint"), "{out}");
    let (ok, out) = zceipt(&["demo"]);
    assert!(ok && out.contains("zceipt verify @examples/testnet/receipt-link.txt"), "{out}");
    let out = Command::new(env!("CARGO_BIN_EXE_zceipt")).arg("demo").current_dir(&dir).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success() && text.contains("zceipt verify 'https://zceipt.xyz/verify/#zip311r1") && !text.contains("@examples/"), "{text}");
}

/// Help text names the binary as it is, describes every option, and shows --account only where
/// a wallet is read.
#[test]
fn help_text_is_complete() {
    let (_, out) = zceipt(&["verify", "--help"]);
    assert!(out.contains("`zceipt verifier-key`") && !out.contains("receipts verifier-key") && !out.contains("--account"), "{out}");
    for cmd in ["inspect", "demo", "doctor", "export", "verifier-key", "serve"] {
        let (_, out) = zceipt(&[cmd, "--help"]);
        assert!(!out.contains("--account"), "{cmd}: {out}");
    }
    let (_, out) = zceipt(&["key", "--help"]);
    assert!(out.contains("--account"), "{out}");
    let (_, out) = zceipt(&["serve", "--help"]);
    assert!(out.contains("--public-url") && out.contains("ZCEIPT_PUBLIC_URL"), "{out}");
    // Short help lists each option with its description on the same line: none may be blank.
    for cmd in ["sign", "income", "reserve", "claim", "key", "siblings", "tag", "delegate", "serve"] {
        let (_, out) = zceipt(&[cmd, "-h"]);
        let lines: Vec<&str> = out.lines().collect();
        for (i, line) in lines.iter().enumerate().filter(|(_, l)| l.trim_start().starts_with('-')) {
            let flag = line.trim_start();
            // Same line (short format), or the indented line below it (long format).
            let same = flag.split_once('>').map(|(_, r)| r).or_else(|| flag.split_once("  ").map(|(_, r)| r)).unwrap_or("");
            let below = lines.get(i + 1).map(|l| l.trim()).filter(|l| !l.starts_with('-')).unwrap_or("");
            assert!(!same.trim().is_empty() || !below.is_empty(), "{cmd}: no description for {flag:?}\n{out}");
        }
    }
}
