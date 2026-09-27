"""rsa-lab CLI: keygen | demo | bench | notes."""
import argparse
import json
import sys

from . import __version__
from .notes import KEY_SIZE_GUIDE, OAEP_NOTE, bench_keygen, format_bench_table
from .rsa import generate_key, malleability_demo


def cmd_keygen(args):
    key = generate_key(args.bits)
    if args.json:
        print(json.dumps({
            "bits": key.bits,
            "public": {"n": str(key.n), "e": key.e},
            "private": {"d": str(key.d), "p": str(key.p), "q": str(key.q)},
            "decimal_digits": len(str(key.n)),
        }, indent=2))
        return 0
    print(f"key: {key.bits}-bit modulus ({len(str(key.n))} decimal digits)")
    print(f"  n = {key.n}")
    print(f"  e = {key.e}")
    print(f"  d = {key.d}")
    print(f"  p = {key.p}")
    print(f"  q = {key.q}")
    print(f"  dp = {key.dp}")
    print(f"  dq = {key.dq}")
    print(f"  q^-1 mod p = {key.qinv}")
    return 0


def cmd_demo(args):
    key = generate_key(args.bits)
    message = args.message
    m = int.from_bytes(message.encode("utf-8"), "big")

    print(f"{key.bits}-bit RSA demo — one message, both decryption paths\n")
    print(f"message:   {message!r}")
    print(f"  m = {m}")
    print(f"  m < n:  {m < key.n}")

    c = key.encrypt(m)
    print(f"\nencrypt:   c = m^e mod n")
    print(f"  c = {c}")

    plain = key.decrypt_plain(c)
    crt = key.decrypt(c)
    print(f"\ndecrypt (plain m = c^d mod n):  {plain}")
    print(f"decrypt (CRT  p/q split)     :  {crt}")
    print(f"CRT matches plain path: {plain == crt == m}")

    round_trip = crt.to_bytes((crt.bit_length() + 7) // 8, "big")
    print(f"recovered text: {round_trip.decode('utf-8', 'replace')!r}")

    print("\nverify: sign with d, check with e")
    s = key.sign(m)
    print(f"  signature == ciphertext here: {s == c}  "
          f"(signature uses d, ciphertext uses e)")
    print(f"  verify(signature) == m: {key.verify(s) == m}")

    demo = malleability_demo(key, m)
    print("\nmalleability: multiply the ciphertext by 2^e (public!)")
    print(f"  tampered plaintext == 2m mod n: "
          f"{demo['tampered_plaintext'] == demo['twice_plaintext']}")
    print(f"  — this is why real encryption needs OAEP padding:")
    print(OAEP_NOTE)
    return 0


def cmd_bench(args):
    sizes = args.sizes or [512, 1024, 2048]
    if args.json:
        print(json.dumps(bench_keygen(sizes), indent=2))
        return 0
    print(format_bench_table(bench_keygen(sizes)))
    print("\n" + KEY_SIZE_GUIDE)
    return 0


def cmd_notes(args):
    print(OAEP_NOTE)
    if args.topic in (None, "all", "keysizes"):
        print("\n" + KEY_SIZE_GUIDE)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="rsa-lab",
        description="RSA laboratory: primality tests, key generation, CRT "
                    "decryption, malleability demo, key-size benchmarks. "
                    "Educational — never use this to protect real data.")
    parser.add_argument("--version", action="version",
                        version=f"rsa-lab {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_keygen = sub.add_parser("keygen", help="generate an RSA key pair")
    p_keygen.add_argument("--bits", type=int, default=2048)
    p_keygen.add_argument("--json", action="store_true")
    p_keygen.set_defaults(func=cmd_keygen)

    p_demo = sub.add_parser("demo", help="encrypt/decrypt walkthrough")
    p_demo.add_argument("--bits", type=int, default=1024)
    p_demo.add_argument("--message", default="hello rsa")
    p_demo.set_defaults(func=cmd_demo)

    p_bench = sub.add_parser("bench", help="key generation and encryption cost")
    p_bench.add_argument("--bits", nargs="*", type=int, dest="sizes",
                         choices=[256, 512, 768, 1024, 1536, 2048, 3072, 4096])
    p_bench.add_argument("--json", action="store_true")
    p_bench.set_defaults(func=cmd_bench)

    p_notes = sub.add_parser("notes", help="OAEP and key-size notes")
    p_notes.add_argument("topic", nargs="?", default="all",
                         choices=["all", "oaep", "keysizes"])
    p_notes.set_defaults(func=cmd_notes)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return 2
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"rsa-lab: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("rsa-lab: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
