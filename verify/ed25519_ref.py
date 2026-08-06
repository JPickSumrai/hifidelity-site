"""
Ed25519 — reference implementation (RFC 8032 / Bernstein et al.)

Python 3 standard library only. Depends on hashlib.sha512 and nothing else.

WHY THIS FILE EXISTS
--------------------
The provenance chain is verifiable with stdlib alone, and that property is
load-bearing: a verifier should not have to install anything, and therefore
does not have to trust a package they did not audit. Adding a signature
scheme should not cost that.

This is the well-known reference implementation of Ed25519. It is correct but
deliberately unoptimised — no constant-time guarantees, no side-channel
hardening. That is acceptable here and nowhere else:

  - It signs a public claim, not a secret.
  - The signature is STANDARD Ed25519. Anyone who does not want to trust this
    file can verify the same signature with openssl, ssh-keygen, PyNaCl,
    python-cryptography, or any other implementation. Nothing about the
    artifact depends on this code being the one that checks it.

Do NOT reuse this for TLS, authentication, or anything where an attacker can
time your operations. Use libsodium.
"""

import hashlib

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


d = -121665 * _inv(121666) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _inv(5) % q
Bx = _xrecover(By)
B = [Bx % q, By % q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e: int):
    # Iterative double-and-add; the recursive form in the published reference
    # nests ~253 deep and is needlessly fragile.
    Q = [0, 1]
    N = P
    while e > 0:
        if e & 1:
            Q = _edwards(Q, N)
        N = _edwards(N, N)
        e >>= 1
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(b))


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("point is not on the curve")
    return P


def _secret_scalar(sk: bytes) -> int:
    h = _H(sk)
    return 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


# ── public API ────────────────────────────────────────────────────────────

def publickey(sk: bytes) -> bytes:
    """32-byte public key from a 32-byte seed."""
    if len(sk) != 32:
        raise ValueError("secret key must be 32 bytes")
    return _encodepoint(_scalarmult(B, _secret_scalar(sk)))


def signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """64-byte Ed25519 signature over m."""
    h = _H(sk)
    a = _secret_scalar(sk)
    r = _Hint(h[b // 8:b // 4] + m)
    R = _scalarmult(B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % l
    return _encodepoint(R) + _encodeint(S)


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    """True if s is a valid Ed25519 signature over m under pk."""
    if len(s) != 64:
        raise ValueError("signature must be 64 bytes")
    if len(pk) != 32:
        raise ValueError("public key must be 32 bytes")
    R = _decodepoint(s[:32])
    A = _decodepoint(pk)
    S = _decodeint(s[32:])
    h = _Hint(_encodepoint(R) + pk + m)
    return _scalarmult(B, S) == _edwards(R, _scalarmult(A, h))


if __name__ == "__main__":
    # RFC 8032 test vector 1 — proves this file is a correct Ed25519.
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk_expect = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig_expect = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                  "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    pk = publickey(sk)
    assert pk.hex() == pk_expect, "public key mismatch"
    sig = signature(b"", sk, pk)
    assert sig.hex() == sig_expect, "signature mismatch"
    assert checkvalid(sig, b"", pk), "verification failed"
    assert not checkvalid(sig, b"tampered", pk), "verified a bad message"
    print("RFC 8032 test vector 1: PASS")
