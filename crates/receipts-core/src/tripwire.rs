//! Secret tripwire: spot viewing keys, spending keys and seed phrases that someone pasted
//! where a receipt belongs, so every surface can refuse them without ever echoing them.
//!
//! A receipt never needs any of these. A viewing key in a support ticket or a log line is
//! the leak Receipts exists to prevent.

/// What kind of secret `text` contains, if any. Never returns the secret itself.
pub fn secret_kind(text: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("uview", "unified full viewing key"),
        ("uivk", "unified incoming viewing key"),
        ("zxviews", "Sapling extended full viewing key"),
        ("zxviewtestsapling", "Sapling extended full viewing key"),
        ("zivks", "Sapling incoming viewing key"),
        ("zivktestsapling", "Sapling incoming viewing key"),
        ("secret-extended-key-", "Sapling extended spending key"),
        ("AGE-SECRET-KEY-1", "age secret key (wallet seed encryption)"),
    ];
    for token in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '=' || c == '&' || c == '?' || c == '#') {
        for (p, kind) in PREFIXES {
            if token.len() > p.len() + 20 && token.starts_with(p) {
                return Some(kind);
            }
        }
        if is_wif(token) {
            return Some("transparent private key (WIF)");
        }
    }
    if looks_like_mnemonic(text) {
        return Some("seed phrase");
    }
    None
}

fn is_base58(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'))
}

/// Base58 WIF keys: mainnet 5…(51) or K…/L…(52); testnet 9…(51) or c…(52).
fn is_wif(t: &str) -> bool {
    let n = t.len();
    is_base58(t) && ((n == 51 && (t.starts_with('5') || t.starts_with('9'))) || (n == 52 && (t.starts_with('K') || t.starts_with('L') || t.starts_with('c'))))
}

/// The BIP 39 English wordlist (2048 words), the list Zcash wallets use for seed phrases.
const BIP39_ENGLISH: &str = include_str!("bip39-english.txt");

fn is_bip39_word(w: &str) -> bool {
    BIP39_ENGLISH.lines().any(|x| x == w)
}

/// A run of 12+ BIP 39 words in a row, like a wallet's seed phrase.
fn looks_like_mnemonic(text: &str) -> bool {
    // Split on whitespace and JSON/URL punctuation, but not digits, so that addresses and
    // hex strings stay whole (and break the run) while "label":"abandon ability…" splits.
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || "\"':,{}[]=&?#+".contains(c))
        .filter(|w| !w.is_empty())
        .collect();
    let mut run = 0;
    let mut best = 0;
    for w in &words {
        let w = w.trim_matches(|c: char| c == '.' || c == ';');
        if (3..=8).contains(&w.len()) && w.chars().all(|c| c.is_ascii_lowercase()) && is_bip39_word(w) {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    // Prose rarely has 12 consecutive words that are all on the BIP 39 list.
    best >= 12
}

#[cfg(test)]
mod tests {
    use super::secret_kind;

    #[test]
    fn spots_secrets() {
        assert_eq!(secret_kind(&format!("uview1{}", "q".repeat(60))), Some("unified full viewing key")); // privacy-lint: allow (test fixture)
        assert_eq!(secret_kind(&format!("{{\"receipt\":\"uviewtest1{}\"}}", "x".repeat(80))), Some("unified full viewing key")); // privacy-lint: allow (test fixture)
        assert_eq!(secret_kind("abandon ability able about above absent absorb abstract absurd abuse access accident"), Some("seed phrase")); // privacy-lint: allow (test fixture)
        assert_eq!(secret_kind(r#"{"payee":"utest1x","label":"abandon ability able about above absent absorb abstract absurd abuse access accident"}"#), Some("seed phrase")); // privacy-lint: allow (test fixture)
        assert_eq!(secret_kind("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"), Some("transparent private key (WIF)")); // privacy-lint: allow (test fixture)
        assert_eq!(secret_kind(&format!("AGE-SECRET-KEY-1{}", "Q".repeat(58))), Some("age secret key (wallet seed encryption)")); // privacy-lint: allow (test fixture)
    }

    #[test]
    fn leaves_receipts_and_addresses_alone() {
        assert_eq!(secret_kind("zrcpt1WlJDVAEBAAAAATK31A9O9qnzNzfQV0FO7NcPf3qawgf"), None);
        assert_eq!(secret_kind("utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa"), None);
        assert_eq!(secret_kind("Order #42 at Kemi's Coffee, two flat whites please"), None);
        assert_eq!(secret_kind("571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73"), None);
        assert_eq!(secret_kind("What you learn: that this order was paid, how much, and the memo. What you don't: who the customer is, their balance or their other payments."), None);
        assert_eq!(secret_kind("Every contribution is a shielded Zcash payment whose sender proved it with a zero-knowledge receipt."), None);
    }
}
