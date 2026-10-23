//! A builder over [`prepare`](crate::prepare) and the verifiers, for wallets: name the network,
//! the transaction, what to disclose and which spends to prove, then prepare (viewing key only)
//! and sign wherever the spending key is.
//!
//! ```ignore
//! let prepared = ReceiptBuilder::new(Network::Testnet, &tx)
//!     .message(b"Invoice 42")
//!     .disclose(1, ovk)
//!     .spend(witness)
//!     .prepare(&pk, &mut rng)?;
//! ```
//!
//! The second half, compiled and run as a test: the public demo wallet's prepared receipt
//! (`examples/testnet/demo`) signed for a new message, then verified against its testnet
//! transaction.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use receipts_core::{sign_prepared, verify_transaction, verifying_key, Network, PreparedReceipt};
//! use zcash_protocol::consensus::{BlockHeight, BranchId, Network::TestNetwork};
//! let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet/demo/");
//! let read = |f: &str| std::fs::read_to_string(format!("{dir}{f}")).unwrap();
//! let bytes = |h: String| (0..h.trim().len()).step_by(2).map(|i| u8::from_str_radix(&h.trim()[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();
//!
//! let prepared = PreparedReceipt::from_text(&read("prepared.txt"))?.with_message(b"challenge:5eed1e55")?;
//! // On the signer: the spending key (this one is public; never fund it).
//! let sk = orchard::keys::SpendingKey::from_bytes(bytes(read("orchard-spending-key.hex")).try_into().unwrap()).unwrap();
//! let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
//! let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
//! let sigs = sign_prepared(prepared.unsigned(), prepared.alphas(), &[ask], &mut rng)?;
//! let receipt = prepared.apply_signatures(sigs)?;
//!
//! let branch = BranchId::for_height(&TestNetwork, BlockHeight::from_u32(4_532_976));
//! let tx = zcash_primitives::transaction::Transaction::read(&bytes(read("tx.hex"))[..], branch)?;
//! let shown = verify_transaction(&verifying_key(), &receipt, Network::Testnet.coin_type(), &tx)?;
//! assert_eq!(shown.msg, b"challenge:5eed1e55");
//! # Ok(())
//! # }
//! ```

use crate::{prepare, Error, Pool, PreparedReceipt, ViewingSpendWitness, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET};
use orchard::{circuit::ProvingKey, keys::OutgoingViewingKey};
use rand_core::CryptoRng;
use zcash_primitives::transaction::Transaction;

/// The network a receipt is for (testnet also covers local regtest chains).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// The coin type the receipt's signatures are bound to.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Mainnet => COIN_TYPE_MAINNET,
            Network::Testnet => COIN_TYPE_TESTNET,
        }
    }
}

/// Collects what a receipt for one transaction discloses and proves.
pub struct ReceiptBuilder<'t> {
    network: Network,
    tx: &'t Transaction,
    spend_pool: Option<Pool>,
    output_pool: Option<Pool>,
    msg: Vec<u8>,
    outputs: Vec<(usize, OutgoingViewingKey)>,
    withheld_memo: Vec<(usize, OutgoingViewingKey)>,
    spends: Vec<ViewingSpendWitness>,
}

impl<'t> ReceiptBuilder<'t> {
    /// A receipt for `tx`, which must be mined (verifiers check that against the chain).
    pub fn new(network: Network, tx: &'t Transaction) -> Self {
        ReceiptBuilder { network, tx, spend_pool: None, output_pool: None, msg: vec![], outputs: vec![], withheld_memo: vec![], spends: vec![] }
    }

    /// The pool of the proven spends. Default: Ironwood if the transaction has an Ironwood
    /// bundle, else Orchard.
    pub fn spends_in(mut self, pool: Pool) -> Self {
        self.spend_pool = Some(pool);
        self
    }

    /// The pool of the disclosed outputs, when it differs from the spends' (an Orchard spend
    /// paying an Ironwood output). Default: the spends' pool.
    pub fn outputs_in(mut self, pool: Pool) -> Self {
        self.output_pool = Some(pool);
        self
    }

    /// The signed message: an invoice number, or `challenge:<hex>` to answer a request.
    pub fn message(mut self, msg: &[u8]) -> Self {
        self.msg = msg.to_vec();
        self
    }

    /// Discloses output action `index` (recipient, amount and memo), opened with `ovk`.
    pub fn disclose(mut self, index: usize, ovk: OutgoingViewingKey) -> Self {
        self.outputs.push((index, ovk));
        self
    }

    /// Discloses output action `index` without its memo (recipient and amount only).
    pub fn disclose_without_memo(mut self, index: usize, ovk: OutgoingViewingKey) -> Self {
        self.withheld_memo.push((index, ovk));
        self
    }

    /// Proves the spend in `witness.index`, from the full viewing key.
    pub fn spend(mut self, witness: ViewingSpendWitness) -> Self {
        self.spends.push(witness);
        self
    }

    /// Makes every proof. The result is signed with
    /// [`PreparedReceipt::sign`] here or [`sign_prepared`](crate::sign_prepared) on another device.
    pub fn prepare(self, pk: &ProvingKey, rng: impl CryptoRng) -> Result<PreparedReceipt, Error> {
        let txid: [u8; 32] = *self.tx.txid().as_ref();
        let spend_pool = self.spend_pool.unwrap_or(if self.tx.ironwood_bundle().is_some() { Pool::Ironwood } else { Pool::Orchard });
        let output_pool = self.output_pool.unwrap_or(spend_pool);
        let bundle = |p: Pool| match p {
            Pool::Ironwood => self.tx.ironwood_bundle(),
            Pool::Orchard => self.tx.orchard_bundle(),
        };
        let spends = bundle(spend_pool).ok_or(Error::NoBundle(spend_pool))?;
        let outputs = bundle(output_pool).ok_or(Error::NoBundle(output_pool))?;
        prepare(pk, self.network.coin_type(), spend_pool, spends, output_pool, outputs, txid, &self.msg, &self.outputs, &self.withheld_memo, &self.spends, rng)
    }
}
