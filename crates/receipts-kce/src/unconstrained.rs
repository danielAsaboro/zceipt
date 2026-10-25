//! Finds witness cells nothing constrains: assigned in a region but never used by an enabled gate,
//! a lookup, a copy to a constrained cell, a constant or a public input. A cell like that lets a
//! malicious prover pick its value freely, the commonest way a hand-written or ported halo2
//! circuit turns unsound. Works from the constraint system's own description and a recorded
//! synthesis, so it needs no knowledge of the circuit.

use halo2_proofs::{
    circuit::Value,
    plonk::{Advice, Any, Assigned, Assignment, Circuit, Column, ConstraintSystem, Error, Fixed, FloorPlanner, Instance, Selector},
};
use pasta_curves::pallas;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};

type Cell = (u8, usize, usize); // (0 advice | 1 fixed | 2 instance, column, row)

#[derive(Default)]
struct Recorder {
    region: String,
    advice: BTreeMap<(usize, usize), String>,
    selectors: BTreeMap<usize, BTreeSet<usize>>,
    copies: Vec<(Cell, Cell)>,
    fixed: BTreeSet<(usize, usize)>,
}

/// A column's index (the field is private, its Debug output is not).
fn index<T: std::fmt::Debug>(c: &T) -> usize {
    let s = format!("{c:?}");
    let i = s.find("index: ").unwrap() + 7;
    s[i..].split(|ch: char| !ch.is_ascii_digit()).next().unwrap().parse().unwrap()
}

fn kind(c: &Column<Any>) -> u8 {
    match c.column_type() {
        Any::Advice => 0,
        Any::Fixed => 1,
        Any::Instance => 2,
    }
}

impl Assignment<pallas::Base> for Recorder {
    fn enter_region<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.region = name_fn().into();
    }
    fn exit_region(&mut self) {}
    fn enable_selector<A, AR>(&mut self, _: A, selector: &Selector, row: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let i: usize = format!("{selector:?}").trim_start_matches("Selector(").split(',').next().unwrap().parse().unwrap();
        self.selectors.entry(i).or_default().insert(row);
        Ok(())
    }
    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<pallas::Base>, Error> {
        Ok(Value::unknown())
    }
    fn assign_advice<V, VR, A, AR>(&mut self, _: A, column: Column<Advice>, row: usize, _: V) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<pallas::Base>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.advice.entry((index(&column), row)).or_insert_with(|| self.region.clone());
        Ok(())
    }
    fn assign_fixed<V, VR, A, AR>(&mut self, _: A, column: Column<Fixed>, row: usize, _: V) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<pallas::Base>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.fixed.insert((index(&column), row));
        Ok(())
    }
    fn copy(&mut self, lc: Column<Any>, lr: usize, rc: Column<Any>, rr: usize) -> Result<(), Error> {
        self.copies.push(((kind(&lc), index(&lc), lr), (kind(&rc), index(&rc), rr)));
        Ok(())
    }
    fn fill_from_row(&mut self, column: Column<Fixed>, row: usize, _: Value<Assigned<pallas::Base>>) -> Result<(), Error> {
        self.fixed.insert((index(&column), row));
        Ok(())
    }
    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }
    fn pop_namespace(&mut self, _: Option<String>) {}
}

/// The text inside the bracket that opens right after `key` (balanced).
fn balanced<'a>(s: &'a str, key: &str, open: char, close: char) -> &'a str {
    let start = s.find(key).unwrap() + key.len();
    let mut depth = 1;
    for (i, ch) in s[start..].char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return &s[start..start + i];
            }
        }
    }
    panic!("unbalanced after {key}")
}

/// Splits `s` at top-level items beginning with `head` ("Gate {" or "Argument {").
fn items<'a>(s: &'a str, head: &str) -> Vec<&'a str> {
    let mut out = vec![];
    let mut at = 0;
    while let Some(i) = s[at..].find(head) {
        let begin = at + i;
        let inner_start = begin + head.len();
        let mut depth = 1;
        let mut end = inner_start;
        for (j, ch) in s[inner_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = inner_start + j;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(&s[inner_start..end]);
        at = end;
    }
    out
}

struct Use {
    selectors: Vec<usize>,
    cells: Vec<(usize, i32)>,
}

fn uses(text: &str) -> Use {
    let sel = Regex::new(r"Selector\(Selector\((\d+), (?:true|false)\)\)").unwrap();
    let cell = Regex::new(r"Advice \{ query_index: \d+, column_index: (\d+), rotation: Rotation\((-?\d+)\) \}").unwrap();
    let mut selectors: Vec<usize> = sel.captures_iter(text).map(|c| c[1].parse().unwrap()).collect();
    selectors.sort();
    selectors.dedup();
    let mut cells: Vec<(usize, i32)> = cell.captures_iter(text).map(|c| (c[1].parse().unwrap(), c[2].parse().unwrap())).collect();
    cells.sort();
    cells.dedup();
    Use { selectors, cells }
}

/// The rows of the (first) public-input column that the circuit ties to a cell. A row left out is
/// a public input the verifier supplies and the proof ignores.
pub fn constrained_instance_rows<C: Circuit<pallas::Base>>(circuit: &C) -> BTreeSet<usize> {
    let mut cs = ConstraintSystem::<pallas::Base>::default();
    let config = C::configure(&mut cs);
    let extra = cs.fixed_column();
    cs.enable_equality(extra);
    let mut rec = Recorder::default();
    C::FloorPlanner::synthesize(&mut rec, circuit, config, vec![extra]).expect("synthesis");
    rec.copies.iter().flat_map(|(a, b)| [a, b]).filter(|c| c.0 == 2 && c.1 == 0).map(|c| c.2).collect()
}

/// The advice cells `circuit` assigns that nothing constrains, as `(column, row, region)`.
pub fn unconstrained_advice<C: Circuit<pallas::Base>>(circuit: &C) -> Vec<(usize, usize, String)> {
    let mut cs = ConstraintSystem::<pallas::Base>::default();
    let config = C::configure(&mut cs);
    let debug = format!("{cs:?}");
    // The circuit's own constant columns are private; any equality-enabled fixed column serves the planner.
    let extra = cs.fixed_column();
    cs.enable_equality(extra);
    let mut rec = Recorder::default();
    C::FloorPlanner::synthesize(&mut rec, circuit, config, vec![extra]).expect("synthesis");
    let max_row = rec.advice.keys().map(|(_, r)| *r).max().unwrap_or(0);

    // What gates and lookups reference, row by row.
    let mut referenced: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut mark = |u: &Use| {
        let rows: Vec<usize> = if u.selectors.is_empty() {
            (0..=max_row).collect()
        } else {
            let mut rows: BTreeSet<usize> = rec.selectors.get(&u.selectors[0]).cloned().unwrap_or_default();
            for s in &u.selectors[1..] {
                let other = rec.selectors.get(s).cloned().unwrap_or_default();
                rows = rows.intersection(&other).copied().collect();
            }
            rows.into_iter().collect()
        };
        for r in rows {
            for (c, rot) in &u.cells {
                let row = r as i64 + *rot as i64;
                if row >= 0 {
                    referenced.insert((*c, row as usize));
                }
            }
        }
    };
    let gates = balanced(&debug, "gates: [", '[', ']');
    for g in items(gates, "Gate {") {
        // The gate's selectors and every cell it queries (a gate multiplies its polynomials by its selector).
        let polys = balanced(g, "polys: [", '[', ']');
        mark(&uses(polys));
    }
    let lookups = balanced(&debug, "lookups: [", '[', ']');
    for l in items(lookups, "Argument {") {
        let inputs = balanced(l, "input_expressions: [", '[', ']');
        // Each input expression carries its own selector; the same selector multiplies all of them.
        mark(&uses(inputs));
    }

    // Copy classes: a class is constrained if any member is referenced, fixed or public.
    let mut parent: BTreeMap<Cell, Cell> = BTreeMap::new();
    fn find(p: &mut BTreeMap<Cell, Cell>, x: Cell) -> Cell {
        let q = *p.entry(x).or_insert(x);
        if q == x {
            return x;
        }
        let r = find(p, q);
        p.insert(x, r);
        r
    }
    for (a, b) in &rec.copies {
        let (ra, rb) = (find(&mut parent, *a), find(&mut parent, *b));
        parent.insert(ra, rb);
    }
    let mut good: BTreeSet<Cell> = BTreeSet::new();
    let cells: Vec<Cell> = parent.keys().copied().collect();
    for c in cells {
        let root = find(&mut parent, c);
        if c.0 != 0 || referenced.contains(&(c.1, c.2)) {
            good.insert(root);
        }
    }
    eprintln!("audit: {} advice cells assigned, {} referenced by gates or lookups, {} copies", rec.advice.len(), referenced.len(), rec.copies.len());
    let mut bad = vec![];
    for ((c, r), region) in &rec.advice {
        if referenced.contains(&(*c, *r)) {
            continue;
        }
        let cell = (0u8, *c, *r);
        if parent.contains_key(&cell) {
            let root = find(&mut parent, cell);
            if good.contains(&root) {
                continue;
            }
        }
        bad.push((*c, *r, region.clone()));
    }
    bad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SiblingCircuit;

    /// A control: the detector must flag a cell nothing constrains, and not one a gate or a copy reaches.
    #[derive(Default)]
    struct Control;
    impl Circuit<pallas::Base> for Control {
        type Config = (Column<Advice>, Column<Advice>, Selector);
        type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Control
        }
        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let (a, b) = (meta.advice_column(), meta.advice_column());
            meta.enable_equality(b);
            let q = meta.selector();
            meta.create_gate("a is zero", |m| {
                let q = m.query_selector(q);
                vec![q * m.query_advice(a, halo2_proofs::poly::Rotation::cur())]
            });
            (a, b, q)
        }
        fn synthesize(&self, (a, b, q): Self::Config, mut l: impl halo2_proofs::circuit::Layouter<pallas::Base>) -> Result<(), Error> {
            use halo2_proofs::circuit::Value;
            l.assign_region(
                || "constrained by the gate",
                |mut r| {
                    q.enable(&mut r, 0)?;
                    r.assign_advice(|| "a", a, 0, || Value::known(pallas::Base::zero()))?;
                    Ok(())
                },
            )?;
            l.assign_region(
                || "free witness",
                |mut r| {
                    r.assign_advice(|| "b", b, 0, || Value::known(pallas::Base::from(7)))?;
                    Ok(())
                },
            )?;
            l.assign_region(
                || "copied to the constrained cell",
                |mut r| {
                    let x = r.assign_advice(|| "a", a, 1, || Value::known(pallas::Base::zero()))?;
                    let y = r.assign_advice(|| "b", b, 1, || Value::known(pallas::Base::zero()))?;
                    r.constrain_equal(x.cell(), y.cell())
                },
            )
        }
    }

    #[test]
    fn the_detector_flags_a_free_witness_and_only_that() {
        // Row 1 of `a` is not under the gate, so its copy partner is free too: both are reported.
        let bad = unconstrained_advice(&Control);
        let regions: Vec<&str> = bad.iter().map(|b| b.2.as_str()).collect();
        assert!(regions.contains(&"free witness"), "{bad:?}");
        assert!(!regions.contains(&"constrained by the gate"), "{bad:?}");
    }

    #[test]
    fn the_sibling_circuit_leaves_no_witness_cell_unconstrained() {
        let c = SiblingCircuit::default();
        let bad = unconstrained_advice(&c);
        let mut by_region: BTreeMap<String, usize> = BTreeMap::new();
        for (_, _, r) in &bad {
            *by_region.entry(r.clone()).or_default() += 1;
        }
        eprintln!("{} unconstrained advice cells: {by_region:?}", bad.len());
        assert!(bad.is_empty(), "{by_region:?}");
    }

    #[test]
    fn the_claim_circuit_leaves_no_witness_cell_unconstrained() {
        for expose_nf in [true, false] {
            let c = orchard::circuit::claim::ClaimCircuit::__empty_for_tests(expose_nf);
            let bad = unconstrained_advice(&c);
            let mut by_region: BTreeMap<String, usize> = BTreeMap::new();
            for (_, _, r) in &bad {
                *by_region.entry(r.clone()).or_default() += 1;
            }
            eprintln!("expose_nf={expose_nf}: {} unconstrained advice cells: {by_region:?}", bad.len());
            assert!(bad.is_empty(), "expose_nf={expose_nf}: {by_region:?}");
        }
    }

    #[test]
    fn every_public_input_of_the_claim_circuit_is_tied_to_the_proof() {
        // Rows: anchor, cv_net x/y, nf_old, rk x/y, cmx, enable_spend, enable_output, then domain and tag.
        for expose_nf in [true, false] {
            let rows = constrained_instance_rows(&orchard::circuit::claim::ClaimCircuit::__empty_for_tests(expose_nf));
            let missing: Vec<usize> = (0..11).filter(|r| !rows.contains(r)).collect();
            eprintln!("expose_nf={expose_nf}: public rows not tied to the circuit: {missing:?} (constrained: {rows:?})");
            // Only the nullifier row (3) may be free, and only when the nullifier is private.
            assert_eq!(missing, if expose_nf { vec![] } else { vec![3] });
        }
        let rows = constrained_instance_rows(&crate::SiblingCircuit::default());
        assert_eq!(rows, [0, 1, 2].into_iter().collect());
    }
}
