"""RSA from first principles: Miller-Rabin primality, key generation,
textbook encryption with a CRT private-key path, and honest notes on why
none of this should ever protect real data. Educational only.

Zero dependencies: everything is Python big integers.
"""
import math
import random

# Small primes for trial division before the expensive test.
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
]

# Bases that make Miller-Rabin deterministic below 3.3 * 10^24.
DETERMINISTIC_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

# 3.3 * 10^24: below this the fixed bases are a proof, not a probability.
DETERMINISTIC_LIMIT = 3317044064679887385961981

DEFAULT_E = 65537


def is_probable_prime(n, rng=None, rounds=40):
    """Miller-Rabin with trial division. Deterministic under 3.3*10^24."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    bases = DETERMINISTIC_BASES if n < DETERMINISTIC_LIMIT else _random_bases(
        n, rng, rounds)
    for a in bases:
        a = a % n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_bases(n, rng, rounds):
    source = rng or random.SystemRandom()
    return [2 + source.randrange(2, n - 3) for _ in range(rounds)]


def generate_prime(bits, rng=None):
    """A prime with exactly `bits` bits."""
    source = rng or random.SystemRandom()
    while True:
        candidate = source.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng):
            return candidate


class RSAKey:
    """An RSA key pair. Public: (n, e). Private: (n, d, p, q)."""

    def __init__(self, n, e, d, p, q):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)
        self.qinv = pow(q, -1, p)
        self.bits = n.bit_length()

    @property
    def lambda_n(self):
        """Carmichael lambda: lcm(p-1, q-1)."""
        return math.lcm(self.p - 1, self.q - 1)

    def public(self):
        return {"n": self.n, "e": self.e}

    def private(self):
        return {"n": self.n, "d": self.d, "p": self.p, "q": self.q}

    def encrypt(self, m):
        if not 0 <= m < self.n:
            raise ValueError("message out of range")
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        """Textbook decryption via the CRT (fast) — the lab's centerpiece."""
        if not 0 <= c < self.n:
            raise ValueError("ciphertext out of range")
        m1 = pow(c, self.dp, self.p)
        m2 = pow(c, self.dq, self.q)
        h = (self.qinv * (m1 - m2)) % self.p
        return (m2 + h * self.q) % self.n

    def decrypt_plain(self, c):
        """Textbook decryption without CRT — the slow reference path."""
        return pow(c, self.d, self.n)

    def sign(self, m):
        """Textbook 'signature' (raw private-key exponentiation)."""
        return pow(m, self.d, self.n)

    def verify(self, s):
        return pow(s, self.e, self.n)


def generate_key(bits=2048, e=DEFAULT_E, rng=None):
    """Generate an RSA key. `bits` is the modulus size (p and q get half)."""
    if bits < 256:
        raise ValueError("modulus below 256 bits is not worth generating")
    half = bits // 2
    while True:
        p = generate_prime(half, rng)
        q = generate_prime(bits - half, rng)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue  # e shares a factor with phi: pick another pair
        return RSAKey(n, e, d, p, q)


def malleability_demo(key, m):
    """Textbook RSA is multiplicative: c*2^e decrypts to 2m. Why OAEP exists."""
    c = key.encrypt(m)
    doubled_c = (c * key.encrypt(2)) % key.n
    return {
        "ciphertext": c,
        "tampered_ciphertext": doubled_c,
        "plaintext": m,
        "tampered_plaintext": key.decrypt(doubled_c),
        "twice_plaintext": (2 * m) % key.n,
    }
