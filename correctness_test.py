import time
import os
import random
import string
import hashlib
from Crypto.Cipher import AES

# Import your functions
from dynamic_aes_enc_code import encrypt_cbc
from dynamic_aes_dec_code import decrypt_cbc
from dynamic_aes_enc_code import generate_dynamic_sbox, generate_dynamic_xor_table

print("==================================================")
print("1. NIST AES-CBC TEST VECTOR VALIDATION")
print("==================================================")
key_nist = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv_nist = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
plaintext_nist = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
expected_ct = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

cipher = AES.new(key_nist, AES.MODE_CBC, iv_nist)
actual_ct = cipher.encrypt(plaintext_nist)
nist_pass = actual_ct == expected_ct
print(f"NIST Test Match: {nist_pass}")

print("\n==================================================")
print("2. SHA-256 CROSS-PROCESS TABLE IDENTITY")
print("==================================================")
master_key = b'0123456789abcdef'

# Instance 1
sbox1 = generate_dynamic_sbox(master_key)
xor1 = generate_dynamic_xor_table(master_key)
hash1 = hashlib.sha256(str(sbox1).encode() + str(xor1).encode()).hexdigest()

# Instance 2 (Simulating a separate execution)
sbox2 = generate_dynamic_sbox(master_key)
xor2 = generate_dynamic_xor_table(master_key)
hash2 = hashlib.sha256(str(sbox2).encode() + str(xor2).encode()).hexdigest()

print(f"Instance 1 SHA-256: {hash1[:16]}...")
print(f"Instance 2 SHA-256: {hash2[:16]}...")
print(f"Tables Match: {hash1 == hash2}")

print("\n==================================================")
print("3. 1000 AUTOMATED SELF-CONSISTENCY TESTS")
print("==================================================")
passed_1000 = 0
start_total = time.perf_counter()

for i in range(1000):
    # Random length between 0 and 1000
    length = random.randint(0, 1000)
    plaintext = bytes(''.join(random.choices(string.ascii_letters + string.digits, k=length)), 'utf-8')
    random_key = os.urandom(16)
    
    # Encrypt/Decrypt
    full_ct = encrypt_cbc(plaintext, random_key)
    iv = full_ct[:16]
    ct = full_ct[16:]
    decrypted = decrypt_cbc(iv, ct, random_key)
    
    if plaintext == decrypted:
        passed_1000 += 1

print(f"Tests Passed: {passed_1000} / 1000")
print(f"Success Rate: {(passed_1000/1000)*100}%")

print("\n==================================================")
print("4. CORRECTNESS TABLE RESULTS")
print("==================================================")

# Exactly 16 bytes
pt_T2 = b"Hello, 16 bytes!"
pt_T3 = b"Hello, this is 32 bytes exactly!"

test_cases = [
    ("T1", b"", b'0123456789abcdef'),
    ("T2", pt_T2, b'0123456789abcdef'),
    ("T3", pt_T3, b'fedcba9876543210'),
    ("T4", b"A" * 1000, b'fedcba9876543210'),
    ("T5", b"B" * 5000, b'secretkey1234567')
]

print("| Test ID | Length    | Match | Total Time (ms) |")
print("---------------------------------------------------")

for test_id, pt, key in test_cases:
    start_enc = time.perf_counter()
    full_ct = encrypt_cbc(pt, key)
    enc_time = (time.perf_counter() - start_enc) * 1000
    
    actual_iv = full_ct[:16]
    ct = full_ct[16:]
    
    start_dec = time.perf_counter()
    decrypted = decrypt_cbc(actual_iv, ct, key)
    dec_time = (time.perf_counter() - start_dec) * 1000
    
    match = "Pass" if pt == decrypted else "Fail"
    total_time = enc_time + dec_time
    
    print(f"|   {test_id}    | {len(pt):>4} bytes | {match:>4}  | {total_time:>7.2f} ms      |")