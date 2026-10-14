//! Binary encoding of receipts, and the `zrcpt1…` text form used in links.
//!
//! ```text
//! unsigned := "ZRCT" | version:u8 = 1 | coin_type:u32le | pool:u8 | txid[32]
//!             | msg_len:u16le | msg
//!             | n_outputs:u8 | { index:u32le | ock[32] }*
//!             | n_spends:u8  | { index:u32le | cv_net[32] | rk[32] | cmx[32]
//!                              | proof_len:u32le | proof }*
//! receipt  := unsigned | { spend_auth_sig[64] } * n_spends
//! ```
//!
//! The text form is `zrcpt1` followed by the unpadded base64url encoding of the receipt.

use crate::{OutputDisclosure, Pool, Receipt, SpendDisclosure, UnsignedReceipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

const MAGIC: &[u8; 4] = b"ZRCT";
const VERSION: u8 = 1;
/// Prefix of the text encoding.
pub const TEXT_PREFIX: &str = "zrcpt1";
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

impl UnsignedReceipt {
    /// The canonical byte encoding that signatures commit to.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(MAGIC);
        v.push(VERSION);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(self.pool.to_byte());
        v.extend_from_slice(&self.txid);
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.push(self.outputs.len() as u8);
        for o in &self.outputs {
            v.extend_from_slice(&o.index.to_le_bytes());
            v.extend_from_slice(&o.ock);
        }
        v.push(self.spends.len() as u8);
        for s in &self.spends {
            v.extend_from_slice(&s.index.to_le_bytes());
            v.extend_from_slice(&s.cv_net);
            v.extend_from_slice(&s.rk);
            v.extend_from_slice(&s.cmx);
            v.extend_from_slice(&(s.proof.len() as u32).to_le_bytes());
            v.extend_from_slice(&s.proof);
        }
        v
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.take(4)? != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let coin_type = r.u32()?;
        let pool_b = r.u8()?;
        let pool = Pool::from_byte(pool_b).ok_or(DecodeError::UnknownPool(pool_b))?;
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
            spends.push(SpendDisclosure {
                index,
                cv_net,
                rk,
                cmx,
                proof,
            });
        }
        Ok(UnsignedReceipt {
            coin_type,
            pool,
            txid,
            msg,
            outputs,
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

    /// `zrcpt1…` text form, safe to put in a URL fragment.
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
