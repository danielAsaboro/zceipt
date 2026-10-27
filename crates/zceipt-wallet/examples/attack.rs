//! Dishonest claimants for the testnet e2e (`scripts/e2e-testnet.sh`): builds the claims a
//! verifier must refuse, from a real wallet, so the refusal is checked against the live chain.
//!
//!     attack claim-spent <wallet> <identity> <domain> <height> <out>   a note the chain had spent by <height>

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["claim-spent", wallet, identity, domain, height, out] => {
            let c = zceipt_wallet::__create_claim_from_spent_note_for_tests(
                &PathBuf::from(wallet),
                &PathBuf::from(identity),
                zceipt_core::Pool::Ironwood,
                domain,
                1_000_000,
                b"attack: spent note",
                Some(height.parse()?),
            )?;
            std::fs::write(out, c.to_text())?;
            eprintln!("wrote {out}");
            Ok(())
        }
        _ => anyhow::bail!("usage: attack claim-spent <wallet> <identity> <domain> <height> <out>"),
    }
}
