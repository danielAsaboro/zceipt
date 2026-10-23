//! The `receipts` binary end to end, offline: the demo, offline verification of every committed
//! example, inspect, check-link, privacy-lint and pay's dry run.

use std::process::Command;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn receipts(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_receipts")).args(args).current_dir(ROOT).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

#[test]
fn demo_runs_every_step() {
    // The default demo: the real receipt and the edited copy, nothing else.
    let (ok, out) = receipts(&["demo"]);
    assert!(ok && out.contains("Halo 2 spend proof and signature valid") && out.contains("refused") && !out.contains("[sandbox]"), "{out}");
    let (ok, out) = receipts(&["demo", "--shop", "--no-wait"]);
    assert!(ok, "{out}");
    for want in ["request.fulfilled ✓", "request.final ✓", "refund.succeeded ✓", "anyone can check it: valid true", "Halo 2 spend proof and signature valid"] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
}

#[test]
fn offline_verification_of_every_example() {
    let h = std::fs::read_to_string(format!("{ROOT}/examples/regtest-crosspool/height")).unwrap();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["verify", "@examples/testnet/receipt.txt", "--raw-tx", "examples/testnet/tx.hex", "--height", "4500997", "--expect-address", "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa"], "Invoice 42"),
        (vec!["verify", "@examples/regtest/receipt.txt", "--regtest", "examples/regtest/heights.toml", "--raw-tx", "examples/regtest/tx.hex", "--height", "222"], "pool      Ironwood"),
        (vec!["verify", "@examples/regtest-orchard/receipt.txt", "--regtest", "examples/regtest-orchard/heights.toml", "--raw-tx", "examples/regtest-orchard/tx.hex", "--height", "212"], "pool      Orchard"),
        (vec!["verify", "@examples/regtest-crosspool/receipt.txt", "--regtest", "examples/regtest-crosspool/heights.toml", "--raw-tx", "examples/regtest-crosspool/tx.hex", "--height", h.trim()], "Orchard to Ironwood"),
        (vec!["verify", "@examples/testnet/deposit-receipt.txt", "--raw-tx", "examples/testnet/deposit-tx1.hex", "--height", "4502928", "--second-raw-tx", "examples/testnet/deposit-tx2.hex"], "EXCHANGE DEPOSIT"),
    ];
    for (args, want) in cases {
        let (ok, out) = receipts(&args);
        assert!(ok && out.contains(want), "{args:?}:\n{out}");
    }
    // JSON output, and failures exit non-zero.
    let (ok, out) = receipts(&["verify", "@examples/testnet/receipt.txt", "--raw-tx", "examples/testnet/tx.hex", "--height", "4500997", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
    assert!(ok && v["valid"] == true, "{out}");
    let (ok, _) = receipts(&["verify", "@examples/testnet/receipt.txt", "--raw-tx", "examples/regtest/tx.hex", "--height", "222"]);
    assert!(!ok, "a receipt checked against another transaction must fail");
    let (ok, out) = receipts(&["verify", "@examples/testnet/deposit-receipt.txt", "--raw-tx", "examples/testnet/deposit-tx1.hex", "--height", "4502928"]);
    assert!(!ok && out.contains("--second-raw-tx"), "{out}");
}

#[test]
fn inspect_check_link_and_privacy_lint() {
    let (ok, out) = receipts(&["inspect", "@examples/testnet/receipt.txt"]);
    assert!(ok && out.contains("571de6e4"), "{out}");
    let (ok, out) = receipts(&["check-link", "zcash:utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa?amount=0.01", "--network", "testnet"]);
    assert!(ok && out.contains("provable with a receipt"), "{out}");
    let (ok, _) = receipts(&["check-link", "zcash:utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa?amount=0.01", "--network", "mainnet"]);
    assert!(!ok);
    // A planted viewing key (built at runtime so this file stays clean) is found and redacted.
    let dir = tempdir();
    let key = format!("{}{}", "uview1", "q".repeat(70));
    std::fs::write(dir.join("app.log"), format!("user pasted {key}\n")).unwrap();
    let (ok, out) = receipts(&["privacy-lint", dir.to_str().unwrap()]);
    assert!(!ok && out.contains("app.log:1") && !out.contains(&key), "{out}");
}

#[test]
fn pay_dry_run_shows_what_it_would_pay() {
    let dir = tempdir();
    std::fs::write(dir.join("keys.toml"), "network = \"test\"\n").unwrap();
    let to = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";
    let link = format!("https://shop.example/?request=0011223344556677&to={to}&min=250000");
    let w = dir.to_str().unwrap();
    let (ok, out) = receipts(&["pay", &link, "-w", w, "-i", "/nonexistent.age", "--dry-run"]);
    assert!(ok && out.contains("0.00250000 ZEC") && out.contains(to) && out.contains("shop.example"), "{out}");
    // A transparent payee can't be proven: refused before anything is sent.
    let (ok, out) = receipts(&["pay", "https://shop.example/?request=0011223344556677&to=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&min=1", "-w", w, "-i", "/x", "--dry-run"]);
    assert!(!ok && out.contains("can't be proven"), "{out}");
}

fn tempdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("receipts-cli-test-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
