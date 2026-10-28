import { seed_from_phrase } from '../../zceipt/pkg/zceipt_wasm.js';

// The 64-byte BIP 39 seed; throws (without quoting the words) if the phrase is invalid.
export async function seedFromPhrase(phrase: string): Promise<Uint8Array> {
  return seed_from_phrase(phrase);
}
