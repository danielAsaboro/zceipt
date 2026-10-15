"""The Pallas curve and the Orchard group hash, from the Zcash protocol specification.

Sections: 5.4.9.6 (Pallas and Vesta), 5.4.9.7 (coordinate extractor), 5.4.9.8 (group hash
into Pallas). Points are affine tuples (x, y); the zero point is None. Python integers only.
"""

import hashlib

# 5.4.9.6
P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001  # base field q_P
R = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001  # group order r_P
B = 5


def inv(x, m=P):
    if x % m == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(x, -1, m)


# Tonelli-Shanks; p - 1 = 2^32 * t with t odd.
_S = 32
_T = (P - 1) >> _S
_NONRESIDUE = next(z for z in range(2, 100) if pow(z, (P - 1) // 2, P) == P - 1)


def is_square(a):
    a %= P
    return a == 0 or pow(a, (P - 1) // 2, P) == 1


def sqrt(a):
    """A square root of a, or None (the spec's sqrt-or-bottom)."""
    a %= P
    if a == 0:
        return 0
    if not is_square(a):
        return None
    m, c, t, r = _S, pow(_NONRESIDUE, _T, P), pow(a, _T, P), pow(a, (_T + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    assert r * r % P == a
    return r


def on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - x * x * x - B) % P == 0


def neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def add(p1, p2, a=0):
    """Complete affine addition on y^2 = x^3 + a x + b (a = 0 for Pallas)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + a) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, pt):
    k %= R
    acc = None
    while k:
        if k & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        k >>= 1
    return acc


def repr_p(pt):
    """repr_P: 32 bytes, x little-endian with the sign of y in the top bit."""
    if pt is None:
        return bytes(32)
    x, y = pt
    return (x + ((y & 1) << 255)).to_bytes(32, "little")


def abst_p(b):
    """abst_P: a point, the zero point (None), or the string 'bot' for an invalid encoding."""
    v = int.from_bytes(b, "little")
    x, ybit = v & ((1 << 255) - 1), v >> 255
    if x >= P:
        return "bot"
    y = sqrt(x * x * x + B)
    if x == 0 and ybit == 0:
        return None
    if y is None:
        return "bot"
    return (x, y) if y & 1 == ybit else (x, P - y)


def decode_point(b, allow_zero=False):
    """A point from its encoding, or raise ValueError (non-canonical, off-curve, or zero)."""
    pt = abst_p(b)
    if pt == "bot":
        raise ValueError("not a Pallas point encoding")
    if pt is None and not allow_zero:
        raise ValueError("the zero point is not allowed here")
    return pt


def extract_p(pt):
    """Extract_P: the x-coordinate (0 for the zero point)."""
    return 0 if pt is None else pt[0]


# ---- 5.4.9.8 Group hash into Pallas (simplified SWU onto iso-Pallas, then the isogeny) ----

ISO_A = 0x18354a2eb0ea8c9c49be2d7258370742b74134581a27a59f92bb4b0b657a014b
ISO_B = 1265
Z = (-13) % P
ISO = [None] + [int(h, 16) for h in """
0e38e38e38e38e38e38e38e38e38e38e4081775473d8375b775f6034aaaaaaab
3509afd51872d88e267c7ffa51cf412a0f93b82ee4b994958cf863b02814fb76
17329b9ec525375398c7d7ac3d98fd13380af066cfeb6d690eb64faef37ea4f7
1c71c71c71c71c71c71c71c71c71c71c8102eea8e7b06eb6eebec06955555580
1d572e7ddc099cff5a607fcce0494a799c434ac1c96b6980c47f2ab668bcd71f
325669becaecd5d11d13bf2a7f22b105b4abf9fb9a1fc81c2aa3af1eae5b6604
1a12f684bda12f684bda12f684bda12f7642b01ad461bad25ad985b5e38e38e4
1a84d7ea8c396c47133e3ffd28e7a09507c9dc17725cca4ac67c31d8140a7dbb
3fb98ff0d2ddcadd303216cce1db9ff11765e924f745937802e2be87d225b234
025ed097b425ed097b425ed097b425ed0ac03e8e134eb3e493e53ab371c71c4f
0c02c5bcca0e6b7f0790bfb3506defb65941a3a4a97aa1b35a28279b1d1b42ae
17033d3c60c68173573b3d7f7d681310d976bbfabbc5661d4d90ab820b12320a
40000000000000000000000000000000224698fc094cf91b992d30ecfffffde5
""".split()]
LAMBDA = _NONRESIDUE  # any fixed nonsquare
THETA = sqrt(Z * inv(LAMBDA) % P)
assert THETA is not None


def _blake2b_512(data):
    return hashlib.blake2b(data, digest_size=64, person=bytes(16)).digest()


def hash_to_field(msg, dst):
    dst2 = dst + bytes([len(dst)])
    b0 = _blake2b_512(bytes(128) + msg + bytes([0, 128]) + bytes([0]) + dst2)
    b1 = _blake2b_512(b0 + bytes([1]) + dst2)
    b2 = _blake2b_512(bytes(x ^ y for x, y in zip(b0, b1)) + bytes([2]) + dst2)
    return [int.from_bytes(b1, "big") % P, int.from_bytes(b2, "big") % P]


def sqrt_ratio(num, div):
    r = num * inv(div) % P
    s = sqrt(r)
    if s is not None:
        return s, 1
    s = sqrt(LAMBDA * r)
    assert s is not None
    return s, 0


def map_to_curve_simple_swu(u):
    """map_to_curve_simple_swu onto iso-Pallas, as written in the specification."""
    zuu = Z * u * u % P
    ta = (zuu * zuu + zuu) % P
    x1_num = ISO_B * (ta + 1) % P
    x_div = ISO_A * (Z if ta == 0 else (-ta) % P) % P
    x_div2 = x_div * x_div % P
    x_div3 = x_div2 * x_div % P
    U = ((x1_num * x1_num + ISO_A * x_div2) * x1_num + ISO_B * x_div3) % P
    x2_num = zuu * x1_num % P
    y1, is_gx1_square = sqrt_ratio(U, x_div3)
    y2 = THETA * zuu % P * u % P * y1 % P
    x_num = x1_num if is_gx1_square else x2_num
    y_ = y1 if is_gx1_square else y2
    y = y_ if (u % 2) == (y_ % 2) else (-y_) % P
    return (x_num * inv(x_div) % P, y)


def iso_map(pt):
    if pt is None:
        return None
    x, y = pt
    x2, x3 = x * x % P, x * x * x % P
    xd = (x2 + ISO[5] * x + ISO[6]) % P
    yd = (x3 + ISO[11] * x2 + ISO[12] * x + ISO[13]) % P
    if xd == 0 or yd == 0:
        return None
    xn = (ISO[1] * x3 + ISO[2] * x2 + ISO[3] * x + ISO[4]) % P
    yn = (ISO[7] * x3 + ISO[8] * x2 + ISO[9] * x + ISO[10]) * y % P
    return (xn * inv(xd) % P, yn * inv(yd) % P)


_GH_CACHE = {}


def group_hash(domain: bytes, msg: bytes):
    """GroupHash^P(D, M)."""
    key = (domain, msg)
    if key in _GH_CACHE:
        return _GH_CACHE[key]
    dst = domain + b"-pallas_XMD:BLAKE2b_SSWU_RO_"
    if len(dst) > 255:
        raise ValueError("domain too long")
    u0, u1 = hash_to_field(msg, dst)
    q = add(map_to_curve_simple_swu(u0), map_to_curve_simple_swu(u1), a=ISO_A)
    pt = iso_map(q)
    assert on_curve(pt)
    _GH_CACHE[key] = pt
    return pt
