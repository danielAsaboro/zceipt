// Writes the Orchard circuit's commitment parameters (k = 11) to the given path.
fn main() {
    let vk = zceipt_core::verifying_key_slow();
    let out = std::env::args().nth(1).expect("output path");
    std::fs::write(&out, vk.params_bytes()).unwrap();
    println!("wrote {out}");
}
