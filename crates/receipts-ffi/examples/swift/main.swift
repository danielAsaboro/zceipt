// Signs the public demo wallet's prepared receipt for a new message and verifies it, from Swift.
// Run: crates/receipts-ffi/examples/swift/run.sh
import Foundation

let dir = CommandLine.arguments[1]
func read(_ f: String) -> String { try! String(contentsOfFile: dir + f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) }
let keyHex = read("orchard-spending-key.hex")
let key = Data(stride(from: 0, to: keyHex.count, by: 2).map { i -> UInt8 in
    let s = keyHex.index(keyHex.startIndex, offsetBy: i)
    return UInt8(keyHex[s ..< keyHex.index(s, offsetBy: 2)], radix: 16)!
})
print(try describePrepared(prepared: read("prepared.txt")))
let receipt = try signPrepared(prepared: read("prepared.txt"), spendingKey: key, message: "challenge:5a1f7e")
let report = try verifyReceipt(receipt: receipt, rawTxHex: read("tx.hex"), height: 4_532_976)
print(report.contains("\"message\":\"challenge:5a1f7e\"") ? "signed and verified from Swift" : "FAILED: \(report)")
print("challenge:", challengeOf(message: "challenge:5a1f7e") ?? "none")
