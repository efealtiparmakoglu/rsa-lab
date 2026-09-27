# rsa-lab

**RSA laboratory in pure Python — Miller-Rabin primality, key generation, CRT decryption, a live malleability demo, and key-size benchmarks. Educational. Zero dependencies.**

```
$ rsa-lab demo --bits 1024 --message hello
1024-bit RSA demo — one message, both decryption paths

message:   'hello'
  m = 448378203247
  m < n:  True

encrypt:   c = m^e mod n
  c = 8a71f3...  (1024 bits of noise)

decrypt (plain m = c^d mod n):  448378203247
decrypt (CRT  p/q split)     :  448378203247
CRT matches plain path: True
recovered text: 'hello'

malleability: multiply the ciphertext by 2^e (public!)
  tampered plaintext == 2m mod n: True
  — this is why real encryption needs OAEP padding
```

RSA is the algorithm everyone half-remembers. rsa-lab rebuilds it from the
bottom: primes found by a Miller-Rabin test you can read, a key schedule
that is just modular inverses, decryption that goes through the Chinese
Remainder Theorem, and a demo that *tamper* a ciphertext with public
information and watch the plaintext change accordingly — because that is
the moment textbook RSA stops looking like encryption.

## Why rsa-lab

- **Real primality testing.** Trial division by the first 37 primes, then
  Miller-Rabin with strong pseudoprime rejection. Deterministic below
  3.3·10²⁴ using the first twelve prime bases, probabilistic above it
  with 40 random bases. Carmichael numbers (561, 1105, 1729…) are in the
  tests as the classic Fermat-liar trap.
- **Key generation you can audit.** `p·q = n` with exact bit length,
  `gcd(e, φ(n)) = 1`, `e·d ≡ 1 (mod λ(n))`, and all four CRT parameters
  (`dp`, `dq`, `q⁻¹ mod p`) verified in the test suite — not assumed.
- **CRT decryption, shown.** Decryption splits into two half-size
  exponentiations mod p and mod q and recombines with the modular inverse
  of q. The plain `c^d mod n` path is kept as the reference and the two
  are asserted equal.
- **The honest part.** The demo multiplies the ciphertext by a *public*
  value and shows the plaintext doubles. That is the malleability that
  makes raw RSA unusable for encryption, and the built-in note explains
  what OAEP actually fixes.
- **Key-size reality check.** `bench` times key generation and encryption
  at 512…4096 bits and prints decimal digit counts, so the 1024-bit
  "decrepit" status stops being folklore.

## Usage

```sh
rsa-lab keygen --bits 2048            # print n, e, d, p, q, dp, dq, qinv
rsa-lab keygen --bits 2048 --json     # machine-readable
rsa-lab demo --bits 1024 --message hi # full walkthrough + malleability
rsa-lab bench --bits 512 1024 2048    # cost table + key-size guide
rsa-lab notes oaep                    # the padding essay
rsa-lab notes keysizes                # the size table alone
```

Exit codes: 0 ok, 2 usage error, 130 interrupted.

## What this is not

Not a crypto library. Textbook RSA has no padding, is deterministic, and
is malleable — real deployments use RSA-OAEP (RFC 8017) for encryption
and RSA-PSS for signatures, usually to wrap an AES key, never data
directly. The notes command says the same thing in more words.

## Development

```sh
python3 -m unittest discover -s tests   # 37 tests
```

All key generation accepts an injected `random.Random`, so the entire
suite is deterministic and finishes in under a second.

## License

MIT — see [LICENSE](LICENSE).
