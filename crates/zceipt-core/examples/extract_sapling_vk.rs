//! Cuts the Sapling Spend verifying key out of `sapling-spend.params` (after its SHA-256 check)
//! into `src/sapling-spend-vk.bin`, which the verifier embeds so it needs no parameter file.
//! `cargo run -p zceipt-core --example extract_sapling_vk [path/to/sapling-spend.params]`
fn main() {
    let path = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| zceipt_core::sapling::default_params_dir().expect("no params directory").join("sapling-spend.params"));
    zceipt_core::sapling::spend_verifying_key_from(&path).expect("the Zcash sapling-spend.params");
    let bytes = std::fs::read(&path).unwrap();
    let vk = groth16::VerifyingKey::<bls12_381::Bls12>::read(&bytes[..]).unwrap();
    let mut out = vec![];
    vk.write(&mut out).unwrap();
    let dst = concat!(env!("CARGO_MANIFEST_DIR"), "/src/sapling-spend-vk.bin");
    std::fs::write(dst, &out).unwrap();
    println!("wrote {} bytes to {dst}", out.len());
}
