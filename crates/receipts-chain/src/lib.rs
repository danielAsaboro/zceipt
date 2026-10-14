//! Chain access for Receipts: network parameters (mainnet, testnet, regtest), fetching
//! transactions from lightwalletd, verifying receipts against the chain, and rebuilding
//! Merkle paths from public data. Shared by the CLI and the API server.

pub mod chain;
pub mod net;

pub use chain::*;
pub use net::Net;
