// Times the verifying key with the shipped parameters and with derived ones.
fn main() {
    let t = std::time::Instant::now();
    let _ = receipts_core::verifying_key();
    println!("cached params: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let _ = receipts_core::verifying_key_slow();
    println!("derived params: {:?}", t.elapsed());
}
