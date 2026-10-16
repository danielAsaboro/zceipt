//! `wallet receipt`: prove one payment this wallet sent (ZIP 311, Orchard/Ironwood), without
//! handing anyone a viewing key. Local integration of Receipts (crates/receipts-wallet).

use std::path::PathBuf;

use anyhow::{anyhow, bail};
use clap::Args;

use crate::data::get_db_paths;

// Options accepted for the `receipt` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,

    /// The transaction to prove (as block explorers show it)
    #[arg(long)]
    txid: String,

    /// A message to sign into the receipt (an invoice number, say)
    #[arg(short, long, default_value = "")]
    message: String,

    /// A shop's proof-request link (`…?request=<code>&to=…&min=…`): the receipt answers it
    #[arg(long)]
    request: Option<String>,

    /// Also sign this address of yours in, for refunds
    #[arg(long)]
    refund_to: Option<String>,

    /// Also prove this wallet controls this address (reveals it to whoever checks the receipt)
    #[arg(long)]
    prove_address: Option<String>,

    /// Also prove where the money came from: the earlier transaction output that created each
    /// note you spent (for example your shielding of an exchange withdrawal)
    #[arg(long)]
    prove_source: bool,

    /// With --prove-source, also reveal each spent note's exact value
    #[arg(long, requires = "prove_source")]
    reveal_source_value: bool,

    /// Show the recipient and amount but keep the memo private
    #[arg(long)]
    withhold_memo: bool,

    /// lightwalletd host:port, used only if a Merkle path must be rebuilt from chain data
    #[arg(short, long)]
    server: Option<String>,

    /// Verifier page for the printed link
    #[arg(long, default_value = "http://127.0.0.1:8723/verify/")]
    link_base: String,

    /// Also write the receipt text to this file
    #[arg(long)]
    out: Option<PathBuf>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let (dir, _) = get_db_paths(wallet_dir.as_ref());
        let mut txid = [0u8; 32];
        hex::decode_to_slice(self.txid.trim(), &mut txid).map_err(|_| anyhow!("--txid must be 64 hex characters"))?;
        txid.reverse();

        let mut lines = Vec::new();
        let mut link_base = self.link_base.clone();
        let request = match &self.request {
            None => None,
            Some(link) => {
                // Same parsing and checks as `receipts create --request`.
                let r = receipts_wallet::parse_request_link(link)?;
                lines.push(format!("challenge:{}", r.code));
                link_base = link.split('#').next().unwrap_or(link).to_string();
                Some(r)
            }
        };
        if !(link_base.starts_with("https://") || link_base.starts_with("http://")) {
            bail!("the verifier link must start with http:// or https://");
        }
        if !self.message.is_empty() {
            lines.push(self.message.clone());
        }
        if let Some(a) = &self.refund_to {
            receipts_wallet::check_refund_address(a)?;
            lines.push(format!("refund-to:{a}"));
        }
        let msg = lines.join("\n");
        if self.server.as_deref().is_some_and(|s| !s.contains(':')) {
            bail!("--server takes host:port (it is only used to rebuild a Merkle path from chain data)");
        }
        let server = self.server.as_deref();

        eprintln!("Building the receipt (a fresh Halo 2 proof for each note you spent)…");
        let (receipt, height) = receipts_wallet::create_receipt(
            &dir,
            std::path::Path::new(&self.identity),
            txid,
            msg.as_bytes(),
            &[],
            None,
            receipts_wallet::WitnessSource::Auto,
            server,
            self.prove_address.as_deref(),
            match (self.prove_source, self.reveal_source_value) {
                (false, _) => None,
                (true, false) => Some(receipts_wallet::SourceMode::HideValue),
                (true, true) => Some(receipts_wallet::SourceMode::RevealValue),
            },
            self.withhold_memo,
        )
        .await?;
        if let Some(r) = &request {
            // Refuse to hand over a "receipt" that doesn't actually answer the request.
            let paid = receipts_wallet::check_answers(&receipt, r, server, None).await?;
            eprintln!("Answers request {}: paid {} zatoshis to the requested address.", r.code, paid);
        }
        let text = receipt.to_text();
        if let Some(out) = &self.out {
            std::fs::write(out, &text)?;
        }
        let u = &receipt.unsigned;
        eprintln!(
            "Receipt for {}: {} output(s) disclosed, spend authority proven for {} note(s); your address and balance stay private.",
            self.txid,
            u.outputs.len(),
            u.spends.len()
        );
        println!("{link_base}#{text}&h={height}");
        Ok(())
    }
}
