"""
Experimental tests for the proposed Dynamic AES-like CBC implementation.

Expected files in the same folder:
  dynamic_aes_enc_code.py
  dynamic_aes_dec_code.py

Run:
  python security_tests.py

Important:
- These are exploratory measurements, NOT a proof of cryptographic security.
- The implementation is a custom AES-like cipher, not standard AES.
- The reduced-key brute-force demo uses only 12 unknown key bits.
"""

import os
import time
import math
import random
import statistics
from collections import Counter

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from dynamic_aes_enc_code import (
    generate_dynamic_sbox,
    generate_dynamic_xor_table,
    key_expansion,
    aes_encrypt_block,
    encrypt_cbc,
)
from dynamic_aes_dec_code import (
    inverse_sbox,
    generate_dynamic_xor_table as generate_dynamic_xor_table_dec,
    key_expansion as dec_key_expansion,
    aes_decrypt_block,
    decrypt_cbc,
)


# ============================================================
# 0. Helpers
# ============================================================

def random_key():
    return os.urandom(16)


def hamming_distance_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("Inputs must have the same length")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def dynamic_encrypt_one_block(block, key):
    """Encrypt one 16-byte block with the proposed block transform."""
    sbox = generate_dynamic_sbox(key)
    xor_table = generate_dynamic_xor_table(key)
    round_keys = key_expansion(key, sbox)
    return aes_encrypt_block(block, round_keys, sbox, xor_table)


def dynamic_decrypt_one_block(block, key):
    """Decrypt one 16-byte block with the proposed block transform."""
    sbox = generate_dynamic_sbox(key)
    inv_sbox = inverse_sbox(sbox)
    _, inv_table = generate_dynamic_xor_table_dec(key)
    round_keys = dec_key_expansion(key, sbox)
    return aes_decrypt_block(block, round_keys, inv_sbox, inv_table)


# ============================================================
# 1. Correctness: CBC round trip and block round trip
# ============================================================

def test_correctness(trials=100):
    print("\\n[1] Correctness / round-trip tests")
    for i in range(trials):
        key = random_key()
        plaintext = os.urandom(random.randrange(0, 300))

        encrypted = encrypt_cbc(plaintext, key)
        iv, ciphertext = encrypted[:16], encrypted[16:]
        recovered = decrypt_cbc(iv, ciphertext, key)

        if recovered != plaintext:
            raise AssertionError(f"CBC round-trip failed on trial {i}")

    for i in range(trials):
        key = random_key()
        block = os.urandom(16)
        encrypted_block = dynamic_encrypt_one_block(block, key)
        recovered_block = dynamic_decrypt_one_block(encrypted_block, key)
        if recovered_block != block:
            raise AssertionError(f"Block round-trip failed on trial {i}")

    print(f"PASS: {trials} CBC round trips and {trials} block round trips")


# ============================================================
# 2. DDT and LAT metrics
# ============================================================

def calculate_ddt(sbox):
    """Return the 256x256 DDT. DDT[a][b] counts x with S(x)^S(x^a)=b."""
    ddt = [[0] * 256 for _ in range(256)]
    for a in range(256):
        for x in range(256):
            b = sbox[x] ^ sbox[x ^ a]
            ddt[a][b] += 1
    return ddt


def calculate_lat(sbox):
    """
    Return absolute Walsh/LAT correlations for all input/output masks.
    W[u][v] = sum_x (-1)^(parity(u&x) xor parity(v&S(x))).
    Bias in counts is |W|/2; normalized correlation is |W|/256.
    """
    lat = [[0] * 256 for _ in range(256)]
    for u in range(256):
        for v in range(256):
            total = 0
            for x in range(256):
                bit = ((u & x).bit_count() ^ (v & sbox[x]).bit_count()) & 1
                total += 1 if bit == 0 else -1
            lat[u][v] = total
    return lat


def sbox_metrics(sbox):
    ddt = calculate_ddt(sbox)
    lat = calculate_lat(sbox)

    # Exclude the trivial input difference a=0 from differential maximum.
    max_ddt = max(ddt[a][b] for a in range(1, 256) for b in range(256))

    # Exclude trivial masks u=v=0; report maximum absolute Walsh coefficient.
    max_walsh = max(
        abs(lat[u][v])
        for u in range(256)
        for v in range(256)
        if not (u == 0 and v == 0)
    )

    return {
        "max_ddt_count": max_ddt,
        "max_differential_probability": max_ddt / 256.0,
        "max_abs_walsh": max_walsh,
        "max_abs_linear_correlation": max_walsh / 256.0,
        "max_abs_linear_bias_count": max_walsh / 2.0,
    }


def test_ddt_lat(dynamic_key_trials=5):
    print("\\n[2] DDT/LAT S-Box analysis")
    aes_sbox = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    ]

    standard = sbox_metrics(aes_sbox)
    print("Standard AES S-Box:", standard)

    results = []
    for _ in range(dynamic_key_trials):
        key = random_key()
        sbox = generate_dynamic_sbox(key)
        metrics = sbox_metrics(sbox)
        results.append(metrics)
        print("Dynamic S-Box:", metrics)

    print("Note: Compare these metrics using identical definitions.")
    print("DDT/LAT properties alone do not prove full-cipher security.")


# ============================================================
# 3. Avalanche test
# ============================================================

def test_avalanche(trials=500):
    print("\\n[3] Avalanche experiment (one-bit plaintext/key changes)")
    plain_distances = []
    key_distances = []

    for _ in range(trials):
        key = random_key()
        block = os.urandom(16)
        c1 = dynamic_encrypt_one_block(block, key)

        bit = random.randrange(128)
        changed_block = bytearray(block)
        changed_block[bit // 8] ^= 1 << (bit % 8)
        c2 = dynamic_encrypt_one_block(bytes(changed_block), key)
        plain_distances.append(hamming_distance_bytes(c1, c2))

        bit = random.randrange(128)
        changed_key = bytearray(key)
        changed_key[bit // 8] ^= 1 << (bit % 8)
        c3 = dynamic_encrypt_one_block(block, bytes(changed_key))
        key_distances.append(hamming_distance_bytes(c1, c3))

    for label, vals in (("Plaintext flip", plain_distances), ("Key flip", key_distances)):
        mean = statistics.mean(vals)
        sd = statistics.stdev(vals)
        print(f"{label}: mean changed bits={mean:.2f}/128, SD={sd:.2f}, "
              f"min={min(vals)}, max={max(vals)}")
    print("A mean near 64 bits is a diffusion observation, not a security proof.")


# ============================================================
# 4. Table generation / encryption performance
# ============================================================

def benchmark_performance(table_trials=1000, encrypt_trials=300):
    print("\\n[4] Performance benchmark")
    key = random_key()
    block = os.urandom(16)

    start = time.perf_counter()
    for _ in range(table_trials):
        generate_dynamic_sbox(key)
        generate_dynamic_xor_table(key)
    table_ms = (time.perf_counter() - start) * 1000 / table_trials
    print(f"Dynamic table generation: {table_ms:.4f} ms per key")

    start = time.perf_counter()
    for _ in range(encrypt_trials):
        dynamic_encrypt_one_block(block, key)
    full_block_ms = (time.perf_counter() - start) * 1000 / encrypt_trials
    print(f"Dynamic one-block encryption INCLUDING table generation: "
          f"{full_block_ms:.4f} ms")

    # Also measure block encryption with tables/key schedule already generated.
    sbox = generate_dynamic_sbox(key)
    xor_table = generate_dynamic_xor_table(key)
    round_keys = key_expansion(key, sbox)

    start = time.perf_counter()
    for _ in range(encrypt_trials):
        aes_encrypt_block(block, round_keys, sbox, xor_table)
    core_ms = (time.perf_counter() - start) * 1000 / encrypt_trials
    print(f"Dynamic one-block encryption EXCLUDING table/key setup: {core_ms:.4f} ms")

    # Standard AES baseline from PyCryptodome, ECB used only for block timing.
    aes = AES.new(key, AES.MODE_ECB)
    start = time.perf_counter()
    for _ in range(encrypt_trials):
        aes.encrypt(block)
    standard_ms = (time.perf_counter() - start) * 1000 / encrypt_trials
    print(f"Standard AES one-block encryption (PyCryptodome): {standard_ms:.6f} ms")
    print("Warning: This compares Python custom code with optimized native AES; "
          "report the implementation difference.")


# ============================================================
# 5. Monobit and Runs tests (simple implementations)
# ============================================================

def bytes_to_bits(data):
    return ''.join(f'{b:08b}' for b in data)


def monobit_test(data):
    bits = bytes_to_bits(data)
    n = len(bits)
    if n == 0:
        raise ValueError("Need nonempty data")
    ones = bits.count("1")
    zeros = n - ones
    # NIST SP 800-22 statistic: S_obs = |sum(2*x_i-1)| / sqrt(n)
    s_obs = abs(ones - zeros) / math.sqrt(n)
    # Approximate p-value using erfc; valid as a screening calculation.
    p_value = math.erfc(s_obs / math.sqrt(2))
    return {"bits": n, "ones_ratio": ones / n, "zeros": zeros, "ones": ones,
            "s_obs": s_obs, "p_value_approx": p_value}


def runs_test(data):
    bits = bytes_to_bits(data)
    n = len(bits)
    if n < 2:
        raise ValueError("Need at least 2 bits")
    pi = bits.count("1") / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {"bits": n, "ones_ratio": pi, "runs": None,
                "p_value_approx": None, "precondition_pass": False}

    runs = 1 + sum(bits[i] != bits[i - 1] for i in range(1, n))
    numerator = abs(runs - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(numerator / denominator) if denominator else 0.0
    return {"bits": n, "ones_ratio": pi, "runs": runs,
            "p_value_approx": p_value, "precondition_pass": True}


def test_randomness(trials=100, plaintext_len=1024):
    print("\\n[5] Ciphertext Monobit and Runs screening tests")
    key = random_key()
    plaintext = os.urandom(plaintext_len)
    encrypted = encrypt_cbc(plaintext, key)
    ciphertext = encrypted[16:]  # exclude IV from this simple test

    mono = monobit_test(ciphertext)
    runs = runs_test(ciphertext)
    print("Monobit:", mono)
    print("Runs:", runs)
    print("Use a recognized NIST SP 800-22 implementation for formal reporting,")
    print("and test many independent ciphertext samples. Passing is not proof of security.")


# ============================================================
# 6. Reduced-key brute-force demonstration (12 unknown bits)
# ============================================================

def make_demo_key(guess, unknown_bits=12):
    """
    Map a small integer into the final key bytes; the first 14 bytes are zero.
    This deliberately creates a tiny key space for a classroom/demo experiment.
    """
    if not 1 <= unknown_bits <= 16:
        raise ValueError("unknown_bits must be between 1 and 16")
    max_guess = 1 << unknown_bits
    if not 0 <= guess < max_guess:
        raise ValueError("guess outside key space")
    return b"\\x00" * 14 + guess.to_bytes(2, "big")


def recover_demo_key_dynamic(iv, first_cipher_block, known_plain_block, unknown_bits=12):
    """
    Exhaustively recover a deliberately reduced key using one CBC block:
      P1 = D_K(C1) XOR IV
    known_plain_block must be the exact 16-byte padded first plaintext block.
    """
    total = 1 << unknown_bits
    start = time.perf_counter()

    for guess in range(total):
        key = make_demo_key(guess, unknown_bits)
        try:
            decrypted = dynamic_decrypt_one_block(first_cipher_block, key)
        except Exception:
            continue
        candidate_plain = xor_bytes(decrypted, iv)
        if candidate_plain == known_plain_block:
            elapsed = time.perf_counter() - start
            return key, guess, guess + 1, elapsed

    elapsed = time.perf_counter() - start
    return None, None, total, elapsed


def test_small_key_recovery(unknown_bits=12):
    print("\\n[6] Reduced-key brute-force demonstration")
    guess = random.randrange(1 << unknown_bits)
    key = make_demo_key(guess, unknown_bits)

    known_plain = b"Known plaintext!"  # exactly 16 bytes
    assert len(known_plain) == 16

    iv = os.urandom(16)
    x = xor_bytes(known_plain, iv)
    c1 = dynamic_encrypt_one_block(x, key)

    recovered_key, recovered_guess, guesses, elapsed = recover_demo_key_dynamic(
        iv, c1, known_plain, unknown_bits
    )

    print(f"Key space: 2^{unknown_bits} = {1 << unknown_bits}")
    print(f"Actual guess index: {guess}")
    print(f"Recovered guess index: {recovered_guess}")
    print(f"Candidates tried: {guesses}")
    print(f"Elapsed: {elapsed:.4f} seconds")
    print(f"Recovered key matches: {recovered_key == key}")
    print("This is brute force over a tiny artificial key space; it does not "
          "demonstrate full 128-bit security or differential/linear resistance.")


# ============================================================
# 7. Preliminary timing-leakage measurements
# ============================================================

def timing_samples_dynamic(keys, block):
    samples = []
    for key in keys:
        # Timing the whole block operation, including key-dependent setup.
        start = time.perf_counter_ns()
        dynamic_encrypt_one_block(block, key)
        samples.append((time.perf_counter_ns() - start) / 1e6)
    return samples


def test_timing_variation(samples_count=300):
    print("\\n[7] Preliminary timing variation test")
    block = os.urandom(16)
    keys = [random_key() for _ in range(samples_count)]
    samples = timing_samples_dynamic(keys, block)

    print(f"Samples: {len(samples)}")
    print(f"Mean: {statistics.mean(samples):.4f} ms")
    print(f"SD: {statistics.stdev(samples):.4f} ms")
    print(f"Min: {min(samples):.4f} ms")
    print(f"Max: {max(samples):.4f} ms")
    print(f"Range: {max(samples) - min(samples):.4f} ms")
    print("This only measures timing variation across keys. It does NOT establish "
          "whether timing leaks key bits. A real leakage test needs controlled "
          "secret-dependent hypotheses, many repeated measurements, and statistical analysis.")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    test_correctness(trials=100)
    test_ddt_lat(dynamic_key_trials=5)
    test_avalanche(trials=500)
    benchmark_performance(table_trials=1000, encrypt_trials=300)
    test_randomness()
    test_small_key_recovery(unknown_bits=12)
    test_timing_variation(samples_count=300)

    print("\\nAll requested exploratory tests finished.")
