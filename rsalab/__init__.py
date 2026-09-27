"""rsa-lab — RSA from first principles: primality tests, key generation,
CRT decryption, malleability demo, key-size benchmarks. Educational only."""
__version__ = "1.0.0"

from .notes import KEY_SIZE_GUIDE, OAEP_NOTE, bench_keygen, format_bench_table
from .rsa import (DEFAULT_E, RSAKey, generate_key, generate_prime,
                  is_probable_prime, malleability_demo)

__all__ = [
    "__version__", "RSAKey", "generate_key", "generate_prime",
    "is_probable_prime", "malleability_demo", "DEFAULT_E",
    "bench_keygen", "format_bench_table", "OAEP_NOTE", "KEY_SIZE_GUIDE",
]
