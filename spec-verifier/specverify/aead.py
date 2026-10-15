"""AEAD_CHACHA20_POLY1305 (RFC 8439), the protocol's Sym (5.4.3) with a zero nonce."""

import hmac
import struct

_M32 = 0xFFFFFFFF


def _rotl(v, c):
    return ((v << c) & _M32) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _M32; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _M32; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32; s[b] = _rotl(s[b] ^ s[c], 7)


def _block(key, counter, nonce):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x + y) & _M32 for x, y in zip(w, st)])


def _chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def _poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return bytes((16 - len(b) % 16) % 16)


def _tag(key, nonce, ct, aad):
    otk = _block(key, 0, nonce)[:32]
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return _poly1305(otk, mac)


def encrypt(key, nonce, pt, aad=b""):
    ct = _chacha20(key, 1, nonce, pt)
    return ct, _tag(key, nonce, ct, aad)


def decrypt(key, nonce, ct_and_tag, aad=b""):
    """The plaintext, or None if authentication fails."""
    if len(ct_and_tag) < 16:
        return None
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    if not hmac.compare_digest(_tag(key, nonce, ct, aad), tag):
        return None
    return _chacha20(key, 1, nonce, ct)


def sym_decrypt(key, ct_and_tag):
    """Sym.Decrypt_K(C): AEAD_CHACHA20_POLY1305 with an all-zero nonce and empty AAD."""
    return decrypt(key, bytes(12), ct_and_tag)
