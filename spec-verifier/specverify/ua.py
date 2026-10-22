"""Unified address decoding (ZIP 316, revision 0): Bech32m without the length limit, then
F4Jumble⁻¹, then typecode/length/value items and the 16-byte HRP padding. Only what the
"was I paid" checks need: the network and the Orchard receiver."""
import hashlib

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3
NETWORKS = {"u": "mainnet", "utest": "testnet", "uregtest": "regtest"}
ORCHARD_TYPECODE = 0x03


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _from_5bit(data):
    acc = bits = 0
    out = bytearray()
    for v in data:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        raise ValueError("invalid padding")
    return bytes(out)


def _h(i, u, n):
    return hashlib.blake2b(u, digest_size=n, person=b"UA_F4Jumble_H" + bytes([i, 0, 0])).digest()


def _g(i, u, n):
    out = b""
    j = 0
    while len(out) < n:
        out += hashlib.blake2b(u, digest_size=64, person=b"UA_F4Jumble_G" + bytes([i]) + j.to_bytes(2, "little")).digest()
        j += 1
    return out[:n]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _f4jumble_inv(m):
    left = min(64, len(m) // 2)
    c, d = m[:left], m[left:]
    y = _xor(c, _h(1, d, left))
    x = _xor(d, _g(1, y, len(d)))
    a = _xor(y, _h(0, x, left))
    b = _xor(x, _g(0, a, len(d)))
    return a + b


def decode(ua: str):
    """Returns (network, {typecode: receiver bytes}); raises ValueError if it isn't a valid UA."""
    s = ua.strip()
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed case")
    s = s.lower()
    hrp, sep, rest = s.rpartition("1")
    if not sep or hrp not in NETWORKS or len(rest) < 6 or any(c not in _CHARSET for c in rest):
        raise ValueError("not a unified address")
    data = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + data) != _BECH32M_CONST:
        raise ValueError("bad checksum")
    m = _f4jumble_inv(_from_5bit(data[:-6]))
    if len(m) < 16 or m[-16:] != hrp.encode().ljust(16, b"\0"):
        raise ValueError("bad padding")
    m, items, i = m[:-16], {}, 0
    while i < len(m):
        if i + 2 > len(m) or m[i] >= 0xFD or m[i + 1] >= 0xFD:
            raise ValueError("unsupported item encoding")
        typecode, length = m[i], m[i + 1]
        value = m[i + 2:i + 2 + length]
        if len(value) != length:
            raise ValueError("truncated item")
        items[typecode] = value
        i += 2 + length
    return NETWORKS[hrp], items


def orchard_receiver(ua: str) -> bytes:
    _, items = decode(ua)
    if ORCHARD_TYPECODE not in items or len(items[ORCHARD_TYPECODE]) != 43:
        raise ValueError("no Orchard receiver")
    return items[ORCHARD_TYPECODE]
