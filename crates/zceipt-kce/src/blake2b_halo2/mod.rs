//! BLAKE2b in Halo 2, from eryxcoop/blake2b_halo2 (Apache-2.0, see LICENSE here), ported from
//! midnight-proofs to zcash's halo2_proofs 0.4 over Pallas. Changes: the import paths, the proof
//! system's API, and a personalization for the initial state (ZIP 32 uses BLAKE2b personalized).
#![allow(missing_docs, dead_code)]

use halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use ff::PrimeField;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

pub(crate) mod base_operations;
pub mod blake2b;
pub mod types;
