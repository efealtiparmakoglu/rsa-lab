"""Honest notes: why textbook RSA is not encryption, and what key sizes cost."""
import time

OAEP_NOTE = """\
Why this is not real encryption
=============================

What you just saw is *textbook RSA*: c = m^e mod n, m = c^d mod n. It is
a trapdoor one-way function, and that is all it is. It is not encryption.

1. DETERMINISTIC. Same plaintext, same ciphertext, always. Encrypt the same
   message twice and the ciphertexts match — that alone breaks every
   standard stream or block cipher mode built on top of it.

2. MALLEABLE. The scheme is multiplicative:
       (m1 * m2)^e = m1^e * m2^e  (mod n)
   So anyone holding the ciphertext can multiply it by 2^e (a public
   value) and the decryption of the result is 2m. Integrity is gone;
   tamper-evidence needs signatures, not encryption.

3. PADDING-LESS. m must be in [0, n). Message *structure* leaks: the same
   number is the same ciphertext everywhere, across every key that shares
   that modulus.

What real implementations do: RSA-OAEP (PKCS#1 v2.1, RFC 8017) randomizes
the message before exponentiation by XORing it with a hash chain seeded
from fresh random bytes (the "seed"), adding a label hash for domain
separation, and rejecting any padding that does not verify. OAEP turns
deterministic, malleable textbook RSA into a randomized, integrity-
protected transform — that is exactly what `openssl pkeyutl -pkeyopt
rsa_padding_mode:oaep` does, and what your TLS library does under the
hood.

The rule of thumb this lab exists to teach: RSA by itself is a signature
primitive and a key-agreement ingredient. For encrypting data, use
hybrid schemes (encrypt a random AES key with RSA-OAEP, then AES-GCM for
the data) or an AEAD directly (age, libsodium's sealed boxes, TLS itself).
"""

KEY_SIZE_GUIDE = """\
Key size, roughly (order of magnitude on a modern laptop):

  bits   modulus    what it means
  ----   -------    --------------------------------------------
   512   154 digits  broken in seconds — never use
  1024   309 digits  factored publicly; deprecated
  2048   617 digits  current baseline, still acceptable
  3072   926 digits  comfortable margin, slower handshakes
  4096  1233 digits  long-term, noticeably slower
 15360                NIST's far-future level

Cost grows with the *cube* of the modulus size for key generation
(primality testing dominates) and with the *square* of it for a raw
modular exponentiation, so 4096-bit keygen is roughly 8x the work of
2048-bit, not 2x.
"""


def bench_keygen(sizes=(512, 1024, 2048), rounds=20):
    """Time key generation and a batch of encryptions per modulus size."""
    from .rsa import generate_key

    rows = []
    for bits in sizes:
        started = time.perf_counter()
        key = generate_key(bits)
        keygen_seconds = time.perf_counter() - started

        started = time.perf_counter()
        for i in range(rounds):
            key.encrypt(42 + i)
        encrypt_each_ms = (time.perf_counter() - started) / rounds * 1000

        rows.append({
            "bits": key.bits,
            "keygen_seconds": round(keygen_seconds, 4),
            "encrypt_ms": round(encrypt_each_ms, 4),
            "decimal_digits": len(str(key.n)),
        })
    return rows


def format_bench_table(rows):
    lines = [
        f"{'bits':>6}  {'digits':>7}  {'keygen (s)':>11}  {'encrypt (ms)':>13}",
        "-" * 46,
    ]
    for row in rows:
        lines.append(
            f"{row['bits']:>6}  {row['decimal_digits']:>7}  "
            f"{row['keygen_seconds']:>11.4f}  {row['encrypt_ms']:>13.4f}")
    return "\n".join(lines)
