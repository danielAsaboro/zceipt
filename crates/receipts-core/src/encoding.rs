//! Binary encoding of receipts, and the `zip311r1…` text form used in links.
//!
//! ```text
//! unsigned := "ZRCT" | version:u8 | coin_type:u32le | pool:u8 | [output_pool:u8 if v3]
//!             | txid[32] | msg_len:u16le | msg
//!             | n_outputs:u8 | { index:u32le | ock[32] }*
//!             | n_spends:u8  | { index:u32le | cv_net[32] | rk[32] | cmx[32]
//!                              | proof_len:u32le | proof | [addr_flag:u8 (0|1) | address proof if 1, v2/v3]
//!                              | [flags:u8 (bit 0 address, bit 1 source) | address proof if bit 0
//!                                 | source proof if bit 1, v4] }*
//! v5 adds, right after the outputs:
//!             n_opened:u8 (≥ 1) | { index:u32le | address[43] | value:u64le | psi[32] | rcm[32] }*
//! source   := txid[32] | index:u32le | value_flag:u8 (0|1)
//!             | { cmx[32] if 0 | value:u64le (>= 1) | address[43] | rseed[32] if 1 }
//!             | proof_len:u32le | proof
//! receipt  := unsigned | { spend_auth_sig[64] } * n_spends
//! ```
//!
//! Version 1: no address proofs. Version 2: at least one spend carries an address proof.
//! Version 3: outputs in another pool than the spends. Version 4: at least one spend carries a
//! source proof; the output pool byte is always present (equal to the spends' pool when the
//! outputs are in the same pool) and each spend has a flags byte. Decoding is strict and canonical: a
//! receipt is accepted only if re-encoding it gives back exactly the same bytes, so one receipt
//! has one encoding.
//!
//! The text form is `zip311r1` followed by the unpadded base64url encoding of the receipt.

use crate::{AddressProof, OpenedOutput, OutputDisclosure, Pool, Receipt, SourceProof, SourceValue, SpendDisclosure, UnsignedReceipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

const MAGIC: &[u8; 4] = b"ZRCT";
const VERSION: u8 = 1;
/// Version 2 adds an optional address proof after each spend.
const VERSION_ADDR: u8 = 2;
/// Version 3: outputs come from a different pool than the spends (an Orchard spend paying an
/// Ironwood output, as every wallet migrating after NU6.3 does). Adds the outputs' pool after
/// the spends' pool, and always carries the per-spend address flag.
const VERSION_XPOOL: u8 = 3;
/// Version 4: at least one spend proves where its note came from (a source proof).
const VERSION_SOURCE: u8 = 4;
/// Version 5: as version 4, plus outputs disclosed without their memo (an opened-outputs list
/// after the outputs). Used exactly when there is at least one.
const VERSION_OPENED: u8 = 5;
/// Prefix of the text encoding.
pub const TEXT_PREFIX: &str = "zip311r1";
const MAX_PROOF_LEN: usize = 1 << 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("not a receipt (bad prefix or magic)")]
    BadMagic,
    #[error("unsupported receipt version {0}")]
    UnsupportedVersion(u8),
    #[error("receipt is truncated")]
    Truncated,
    #[error("unknown pool {0}")]
    UnknownPool(u8),
    #[error("version 3 must name an output pool different from the spends' pool")]
    SamePool,
    #[error("not in canonical form (bad flag, or the wrong version for its contents)")]
    NonCanonical,
    #[error("trailing bytes after the receipt")]
    TrailingBytes,
    #[error("field too large")]
    TooLarge,
    #[error("invalid base64")]
    Base64,
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn arr32(&mut self) -> Result<[u8; 32], DecodeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

fn encode_address(v: &mut Vec<u8>, a: &AddressProof) {
    v.extend_from_slice(&a.address);
    v.extend_from_slice(&a.rho);
    v.extend_from_slice(&a.rseed);
    v.extend_from_slice(&a.nf);
    v.extend_from_slice(&a.cv_net);
    v.extend_from_slice(&a.cmx);
    v.extend_from_slice(&(a.proof.len() as u32).to_le_bytes());
    v.extend_from_slice(&a.proof);
}

fn read_address(r: &mut Reader<'_>) -> Result<AddressProof, DecodeError> {
    let address: [u8; 43] = r.take(43)?.try_into().unwrap();
    let rho = r.arr32()?;
    let rseed = r.arr32()?;
    let nf = r.arr32()?;
    let cv_net = r.arr32()?;
    let cmx = r.arr32()?;
    let len = r.u32()? as usize;
    if len > MAX_PROOF_LEN {
        return Err(DecodeError::TooLarge);
    }
    Ok(AddressProof { address, rho, rseed, nf, cv_net, cmx, proof: r.take(len)?.to_vec() })
}

impl UnsignedReceipt {
    /// The canonical byte encoding that signatures commit to.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let xpool = self.output_pool.filter(|p| *p != self.pool);
        let with_opened = !self.opened.is_empty();
        let with_source = with_opened || self.spends.iter().any(|s| s.source.is_some());
        let with_addr = xpool.is_some() || self.spends.iter().any(|s| s.address.is_some());
        v.extend_from_slice(MAGIC);
        v.push(if with_opened {
            VERSION_OPENED
        } else if with_source {
            VERSION_SOURCE
        } else if xpool.is_some() {
            VERSION_XPOOL
        } else if with_addr {
            VERSION_ADDR
        } else {
            VERSION
        });
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(self.pool.to_byte());
        if with_source {
            v.push(xpool.unwrap_or(self.pool).to_byte());
        } else if let Some(p) = xpool {
            v.push(p.to_byte());
        }
        v.extend_from_slice(&self.txid);
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.push(self.outputs.len() as u8);
        for o in &self.outputs {
            v.extend_from_slice(&o.index.to_le_bytes());
            v.extend_from_slice(&o.ock);
        }
        if with_opened {
            v.push(self.opened.len() as u8);
            for o in &self.opened {
                v.extend_from_slice(&o.index.to_le_bytes());
                v.extend_from_slice(&o.address);
                v.extend_from_slice(&o.value.to_le_bytes());
                v.extend_from_slice(&o.psi);
                v.extend_from_slice(&o.rcm);
            }
        }
        v.push(self.spends.len() as u8);
        for s in &self.spends {
            v.extend_from_slice(&s.index.to_le_bytes());
            v.extend_from_slice(&s.cv_net);
            v.extend_from_slice(&s.rk);
            v.extend_from_slice(&s.cmx);
            v.extend_from_slice(&(s.proof.len() as u32).to_le_bytes());
            v.extend_from_slice(&s.proof);
            if with_source {
                // Bits 0 and 1 are disjoint, so `|`, `^` and `+` all give the same byte.
                v.push(u8::from(s.address.is_some()) | (u8::from(s.source.is_some()) << 1));
                if let Some(a) = &s.address {
                    encode_address(&mut v, a);
                }
                if let Some(src) = &s.source {
                    v.extend_from_slice(&src.txid);
                    v.extend_from_slice(&src.index.to_le_bytes());
                    match &src.value {
                        SourceValue::Hidden { cmx } => {
                            v.push(0);
                            v.extend_from_slice(cmx);
                        }
                        SourceValue::Revealed { value, address, rseed } => {
                            v.push(1);
                            v.extend_from_slice(&value.to_le_bytes());
                            v.extend_from_slice(address);
                            v.extend_from_slice(rseed);
                        }
                    }
                    v.extend_from_slice(&(src.proof.len() as u32).to_le_bytes());
                    v.extend_from_slice(&src.proof);
                }
            } else if with_addr {
                match &s.address {
                    None => v.push(0),
                    Some(a) => {
                        v.push(1);
                        encode_address(&mut v, a);
                    }
                }
            }
        }
        v
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.take(4)? != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = r.u8()?;
        if !(VERSION..=VERSION_OPENED).contains(&version) {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let coin_type = r.u32()?;
        let pool_b = r.u8()?;
        let pool = Pool::from_byte(pool_b).ok_or(DecodeError::UnknownPool(pool_b))?;
        let output_pool = if version == VERSION_XPOOL {
            let b = r.u8()?;
            let p = Pool::from_byte(b).ok_or(DecodeError::UnknownPool(b))?;
            if p == pool {
                return Err(DecodeError::SamePool);
            }
            Some(p)
        } else if version >= VERSION_SOURCE {
            let b = r.u8()?;
            let p = Pool::from_byte(b).ok_or(DecodeError::UnknownPool(b))?;
            (p != pool).then_some(p)
        } else {
            None
        };
        let txid = r.arr32()?;
        let msg_len = r.u16()? as usize;
        let msg = r.take(msg_len)?.to_vec();
        let n_out = r.u8()? as usize;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(OutputDisclosure {
                index: r.u32()?,
                ock: r.arr32()?,
            });
        }
        let mut opened = Vec::new();
        if version == VERSION_OPENED {
            for _ in 0..r.u8()? {
                let index = r.u32()?;
                let address: [u8; 43] = r.take(43)?.try_into().unwrap();
                let value = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
                opened.push(OpenedOutput { index, address, value, psi: r.arr32()?, rcm: r.arr32()? });
            }
        }
        let n_sp = r.u8()? as usize;
        let mut spends = Vec::with_capacity(n_sp);
        for _ in 0..n_sp {
            let index = r.u32()?;
            let cv_net = r.arr32()?;
            let rk = r.arr32()?;
            let cmx = r.arr32()?;
            let len = r.u32()? as usize;
            if len > MAX_PROOF_LEN {
                return Err(DecodeError::TooLarge);
            }
            let proof = r.take(len)?.to_vec();
            let flag = if version >= VERSION_ADDR { r.u8()? } else { 0 };
            let max_flag = if version >= VERSION_SOURCE { 3 } else { 1 };
            if flag > max_flag {
                return Err(DecodeError::NonCanonical);
            }
            let address = if flag & 1 == 1 { Some(read_address(r)?) } else { None };
            let source = if flag & 2 == 2 {
                let txid = r.arr32()?;
                let index = r.u32()?;
                let value = match r.u8()? {
                    0 => SourceValue::Hidden { cmx: r.arr32()? },
                    1 => {
                        let value = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
                        if value == 0 {
                            return Err(DecodeError::NonCanonical);
                        }
                        let address: [u8; 43] = r.take(43)?.try_into().unwrap();
                        SourceValue::Revealed { value, address, rseed: r.arr32()? }
                    }
                    _ => return Err(DecodeError::NonCanonical),
                };
                let len = r.u32()? as usize;
                if len > MAX_PROOF_LEN {
                    return Err(DecodeError::TooLarge);
                }
                Some(SourceProof { txid, index, value, proof: r.take(len)?.to_vec() })
            } else {
                None
            };
            spends.push(SpendDisclosure {
                index,
                cv_net,
                rk,
                cmx,
                proof,
                address,
                source,
            });
        }
        Ok(UnsignedReceipt {
            coin_type,
            pool,
            output_pool,
            txid,
            msg,
            outputs,
            opened,
            spends,
        })
    }
}

impl Receipt {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.unsigned.encode();
        for s in &self.spend_auth_sigs {
            v.extend_from_slice(s);
        }
        v
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader { buf: bytes };
        let unsigned = UnsignedReceipt::read(&mut r)?;
        // Canonical: the signed encoding must be exactly the bytes we were given (rejects a v2
        // with no address proof, or other re-labellings that would decode to the same receipt).
        let consumed = bytes.len() - r.buf.len();
        if unsigned.encode() != bytes[..consumed] {
            return Err(DecodeError::NonCanonical);
        }
        let mut spend_auth_sigs = Vec::with_capacity(unsigned.spends.len());
        for _ in 0..unsigned.spends.len() {
            spend_auth_sigs.push(r.take(64)?.try_into().unwrap());
        }
        if !r.buf.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Receipt {
            unsigned,
            spend_auth_sigs,
        })
    }

    /// `zip311r1…` text form, safe to put in a URL fragment.
    pub fn to_text(&self) -> String {
        format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, DecodeError> {
        let s = s.trim();
        let body = s.strip_prefix(TEXT_PREFIX).ok_or(DecodeError::BadMagic)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| DecodeError::Base64)?;
        Self::from_bytes(&bytes)
    }
}

/// Prefix of the text encoding of a prepared (proved, not yet signed) receipt.
pub const PREPARED_TEXT_PREFIX: &str = "zip311u1";

/// A prepared receipt as it travels from the watch-only machine that made the proofs to the
/// signer. It holds each spend's `alpha`, which links the receipt to its spends: keep it between
/// the two machines.
///
/// ```text
/// prepared := unsigned | { alpha[32] } * n_spends
/// text     := "zip311u1" || base64url_nopad(prepared)
/// ```
impl crate::PreparedReceipt {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.unsigned().encode();
        for a in self.alphas() {
            v.extend_from_slice(&ff::PrimeField::to_repr(a));
        }
        v
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader { buf: bytes };
        let unsigned = UnsignedReceipt::read(&mut r)?;
        let consumed = bytes.len() - r.buf.len();
        if unsigned.encode() != bytes[..consumed] {
            return Err(DecodeError::NonCanonical);
        }
        let mut alphas = Vec::with_capacity(unsigned.spends.len());
        for _ in 0..unsigned.spends.len() {
            let repr = r.arr32()?;
            alphas.push(Option::from(<pasta_curves::pallas::Scalar as ff::PrimeField>::from_repr(repr)).ok_or(DecodeError::NonCanonical)?);
        }
        if !r.buf.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(crate::PreparedReceipt::from_parts(unsigned, alphas))
    }

    pub fn to_text(&self) -> String {
        format!("{PREPARED_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, DecodeError> {
        let body = s.trim().strip_prefix(PREPARED_TEXT_PREFIX).ok_or(DecodeError::BadMagic)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| DecodeError::Base64)?;
        Self::from_bytes(&bytes)
    }
}

/// Prefix of the text encoding of a batch of receipts.
pub const BATCH_TEXT_PREFIX: &str = "zip311b1";
const BATCH_MAGIC: &[u8; 4] = b"ZRCB";
const MAX_BATCH: usize = 256;

/// Several receipts shared as one link, e.g. every payout of a grant round.
///
/// ```text
/// batch := "ZRCB" | version:u8 = 1 | count:u16le | { len:u32le | receipt }*
/// text  := "zip311b1" || base64url_nopad(batch)
/// ```
///
/// Each receipt is verified on its own and signs `batch:<id> <i>/<n>` in its message, so the
/// set cannot be silently extended, truncated or reordered without breaking a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptBatch {
    pub receipts: Vec<Receipt>,
}

impl ReceiptBatch {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(BATCH_MAGIC);
        v.push(VERSION);
        v.extend_from_slice(&(self.receipts.len() as u16).to_le_bytes());
        for r in &self.receipts {
            let b = r.to_bytes();
            v.extend_from_slice(&(b.len() as u32).to_le_bytes());
            v.extend_from_slice(&b);
        }
        v
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader { buf: bytes };
        if r.take(4)? != BATCH_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let n = r.u16()? as usize;
        if n == 0 || n > MAX_BATCH {
            return Err(DecodeError::TooLarge);
        }
        let mut receipts = Vec::with_capacity(n);
        for _ in 0..n {
            let len = r.u32()? as usize;
            receipts.push(Receipt::from_bytes(r.take(len)?)?);
        }
        if !r.buf.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(ReceiptBatch { receipts })
    }

    pub fn to_text(&self) -> String {
        format!("{BATCH_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, DecodeError> {
        let body = s.trim().strip_prefix(BATCH_TEXT_PREFIX).ok_or(DecodeError::BadMagic)?;
        Self::from_bytes(&URL_SAFE_NO_PAD.decode(body).map_err(|_| DecodeError::Base64)?)
    }
}

/// Parses the `batch:<id> <i>/<n>` line a batched receipt signs.
pub fn batch_position(msg: &[u8]) -> Option<(String, u16, u16)> {
    let text = std::str::from_utf8(msg).ok()?;
    // Only the first line, as SPEC.md says: a `batch:` line further down is ordinary text.
    let line = text.lines().next()?.strip_prefix("batch:")?;
    let (id, pos) = line.split_once(' ')?;
    let (i, n) = pos.split_once('/')?;
    // Strict: a non-empty id, and ASCII digits only (u16::from_str would also take a leading `+`).
    // Canonical decimal: no leading zeros, at most 5 digits (u16).
    let digits = |s: &str| !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if id.is_empty() || !digits(i) || !digits(n) {
        return None;
    }
    Some((id.to_string(), i.parse().ok()?, n.parse().ok()?))
}

/// Checks that the batch is complete and consistent: one id, one network, positions 1..=n each
/// exactly once, and no output disclosed twice (two receipts for the same output would count one payment
/// twice in the batch total).
pub fn check_batch(batch: &ReceiptBatch) -> Result<String, String> {
    let n = batch.receipts.len();
    let mut id = None;
    let mut seen = vec![false; n];
    let mut outputs = std::collections::BTreeSet::new();
    let coin_type = batch.receipts.first().map(|r| r.unsigned.coin_type);
    for r in &batch.receipts {
        let u = &r.unsigned;
        if Some(u.coin_type) != coin_type {
            return Err("receipts for different networks in one batch".into());
        }
        let pool = u.output_pool.unwrap_or(u.pool) as u8;
        for index in u.outputs.iter().map(|o| o.index).chain(u.opened.iter().map(|o| o.index)) {
            if !outputs.insert((u.txid, pool, index)) {
                return Err(format!("output {index} of transaction {} is disclosed more than once", crate::display_txid(&u.txid)));
            }
        }
        let (bid, i, total) = batch_position(&r.unsigned.msg).ok_or("a receipt in the batch has no batch position")?;
        if total as usize != n {
            return Err(format!("receipt says the batch has {total} payments, but it contains {n}"));
        }
        if i == 0 || i as usize > n || std::mem::replace(&mut seen[i as usize - 1], true) {
            return Err(format!("bad or repeated batch position {i}"));
        }
        match &id {
            None => id = Some(bid),
            Some(x) if *x != bid => return Err("receipts from different batches".into()),
            _ => {}
        }
    }
    Ok(id.unwrap_or_default())
}
