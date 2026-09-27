import json
import random
import unittest

from rsalab.cli import main
from rsalab.notes import KEY_SIZE_GUIDE, OAEP_NOTE, bench_keygen, format_bench_table
from rsalab.rsa import (DEFAULT_E, DETERMINISTIC_LIMIT, generate_key,
                        generate_prime, is_probable_prime, malleability_demo)


class PrimalityTests(unittest.TestCase):
    def test_small_primes_pass(self):
        for p in (2, 3, 5, 7, 11, 13, 97, 101, 8191, 131071):
            self.assertTrue(is_probable_prime(p), p)

    def test_composites_rejected(self):
        for n in (0, 1, 4, 6, 9, 15, 21, 100, 561, 1105, 7919 * 2):
            self.assertFalse(is_probable_prime(n), n)

    def test_carmichael_numbers_rejected(self):
        # Carmichael numbers fool Fermat but not Miller-Rabin
        for n in (561, 1105, 1729, 2465, 2821, 6601):
            self.assertFalse(is_probable_prime(n), n)

    def test_large_prime(self):
        self.assertTrue(is_probable_prime(2**31 - 1))  # 2147483647, Mersenne

    def test_large_composite(self):
        self.assertFalse(is_probable_prime(2**31 - 3))

    def test_deterministic_under_limit(self):
        p = generate_prime(80, random.Random(7))
        self.assertTrue(is_probable_prime(p))
        self.assertLess(p, DETERMINISTIC_LIMIT)

    def test_carmichael_561_base_2_rejected(self):
        # strong witness: 2^(d) != 1 and != -1 chain fails for 561
        self.assertFalse(is_probable_prime(561, rounds=1))

    def test_seed_reproducible_prime(self):
        a = generate_prime(64, random.Random(42))
        b = generate_prime(64, random.Random(42))
        self.assertEqual(a, b)

    def test_generate_prime_exact_bit_length(self):
        for bits in (64, 128, 256):
            p = generate_prime(bits, random.Random(bits))
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(is_probable_prime(p))

    def test_generate_prime_is_odd_and_high_bit_set(self):
        p = generate_prime(96, random.Random(1))
        self.assertEqual(p & 1, 1)
        self.assertEqual(p >> 95, 1)


class KeyTests(unittest.TestCase):
    def setUp(self):
        self.key = generate_key(512, rng=random.Random(1234))

    def test_modulus_size(self):
        self.assertEqual(self.key.n.bit_length(), 512)
        self.assertEqual(self.key.bits, 512)

    def test_n_is_product_of_primes(self):
        self.assertEqual(self.key.p * self.key.q, self.key.n)
        self.assertTrue(is_probable_prime(self.key.p))
        self.assertTrue(is_probable_prime(self.key.q))
        self.assertNotEqual(self.key.p, self.key.q)

    def test_e_is_65537(self):
        self.assertEqual(self.key.e, DEFAULT_E)

    def test_d_inverts_e_mod_lambda(self):
        self.assertEqual((self.key.e * self.key.d) % self.key.lambda_n, 1)

    def test_d_inverts_e_mod_phi(self):
        phi = (self.key.p - 1) * (self.key.q - 1)
        self.assertEqual((self.key.e * self.key.d) % phi, 1)

    def test_crt_parameters(self):
        self.assertEqual(self.key.dp, self.key.d % (self.key.p - 1))
        self.assertEqual(self.key.dq, self.key.d % (self.key.q - 1))
        self.assertEqual((self.key.q * self.key.qinv) % self.key.p, 1)

    def test_rejects_tiny_modulus(self):
        with self.assertRaises(ValueError):
            generate_key(128)

    def test_large_keygen(self):
        key = generate_key(1024, rng=random.Random(99))
        self.assertEqual(key.n.bit_length(), 1024)


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        self.key = generate_key(512, rng=random.Random(2024))

    def test_round_trip(self):
        m = 0xDEADBEEF
        self.assertEqual(self.key.decrypt(self.key.encrypt(m)), m)

    def test_round_trip_large_message(self):
        m = 10**120
        self.assertEqual(self.key.decrypt(self.key.encrypt(m)), m)

    def test_round_trip_edges(self):
        for m in (0, 1, 2, self.key.n - 1):
            self.assertEqual(self.key.decrypt(self.key.encrypt(m)), m), m

    def test_crt_matches_plain_path(self):
        for m in (0, 1, 42, 123456789, self.key.n - 2):
            c = self.key.encrypt(m)
            self.assertEqual(self.key.decrypt(c), self.key.decrypt_plain(c))

    def test_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            self.key.encrypt(self.key.n)
        with self.assertRaises(ValueError):
            self.key.decrypt(self.key.n)
        with self.assertRaises(ValueError):
            self.key.encrypt(-1)

    def test_encrypt_is_deterministic(self):
        # the very property that makes textbook RSA unusable for encryption
        m = 1234567890
        self.assertEqual(self.key.encrypt(m), self.key.encrypt(m))

    def test_sign_verify(self):
        m = 987654321
        self.assertEqual(self.key.verify(self.key.sign(m)), m)

    def test_public_dict_shape(self):
        self.assertEqual(self.key.public(), {"n": self.key.n, "e": self.key.e})
        self.assertEqual(self.key.private()["p"], self.key.p)


class MalleabilityTests(unittest.TestCase):
    def test_multiplicative_tamper(self):
        key = generate_key(512, rng=random.Random(555))
        m = 31337
        demo = malleability_demo(key, m)
        self.assertEqual(demo["tampered_plaintext"], demo["twice_plaintext"])
        self.assertNotEqual(demo["plaintext"], demo["tampered_plaintext"])

    def test_different_key_same_message_differs(self):
        k1 = generate_key(512, rng=random.Random(1))
        k2 = generate_key(512, rng=random.Random(2))
        self.assertNotEqual(k1.encrypt(42), k2.encrypt(42))


class NotesTests(unittest.TestCase):
    def test_oaep_note_mentions_padding(self):
        self.assertIn("OAEP", OAEP_NOTE)
        self.assertIn("MALLEABLE", OAEP_NOTE)

    def test_key_size_guide_lists_baseline(self):
        self.assertIn("2048", KEY_SIZE_GUIDE)
        self.assertIn("4096", KEY_SIZE_GUIDE)

    def test_bench_small_sizes(self):
        rows = bench_keygen((256, 512), rounds=3)
        self.assertEqual([r["bits"] for r in rows], [256, 512])
        for row in rows:
            self.assertGreater(row["keygen_seconds"], 0)
            self.assertGreater(row["decimal_digits"], 70)

    def test_bench_table_renders(self):
        table = format_bench_table(bench_keygen((256,), rounds=1))
        self.assertIn("bits", table)
        self.assertIn("256", table)


class CliTests(unittest.TestCase):
    def test_keygen_json(self):
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["keygen", "--bits", "256", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["bits"], 256)
        self.assertEqual(payload["public"]["e"], 65537)

    def test_demo_runs(self):
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["demo", "--bits", "256", "--message", "hi"])
        self.assertEqual(code, 0)
        self.assertIn("CRT matches plain path: True", buffer.getvalue())

    def test_notes_topic(self):
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["notes", "oaep"])
        self.assertEqual(code, 0)
        self.assertNotIn("decimal_digits", buffer.getvalue())

    def test_no_command_prints_help(self):
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main([])
        self.assertEqual(code, 2)
        self.assertIn("usage", buffer.getvalue())

    def test_bad_bits_rejected(self):
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["keygen", "--bits", "100", "--json"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
