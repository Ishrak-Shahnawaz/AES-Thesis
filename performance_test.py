import time
import os

# Import your dynamic functions
from dynamic_aes_enc_code import encrypt_cbc, generate_dynamic_sbox, generate_dynamic_xor_table, key_expansion, aes_encrypt_block
from dynamic_aes_dec_code import decrypt_cbc, inverse_sbox, aes_decrypt_block, generate_dynamic_xor_table as dec_gen_xor

# --- PURE PYTHON STANDARD AES S-BOX ---
STD_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def std_sub_bytes(state):
    for i in range(4):
        for j in range(4): state[i][j] = STD_SBOX[state[i][j]]

def std_shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def std_xtime(a):
    if a & 0x80: return ((a << 1) ^ 0x1b) & 0xff
    return (a << 1) & 0xff

def std_mix_column(col):
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ std_xtime(col[0] ^ col[1])
    col[1] ^= t ^ std_xtime(col[1] ^ col[2])
    col[2] ^= t ^ std_xtime(col[2] ^ col[3])
    col[3] ^= t ^ std_xtime(col[3] ^ u)

def std_mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        std_mix_column(col)
        for j in range(4): state[j][i] = col[j]

def std_add_round_key(state, round_key):
    for i in range(4):
        for j in range(4): state[i][j] ^= round_key[i][j]

def std_aes_encrypt_block(plaintext_block, round_keys):
    state = [[plaintext_block[j*4 + i] for j in range(4)] for i in range(4)]
    std_add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        std_sub_bytes(state)
        std_shift_rows(state)
        std_mix_columns(state)
        std_add_round_key(state, round_keys[rnd])
    std_sub_bytes(state)
    std_shift_rows(state)
    std_add_round_key(state, round_keys[10])
    return bytes([state[j][i] for i in range(4) for j in range(4)])

def std_aes_cbc_encrypt(plaintext, key):
    padded = pad(plaintext, 16)
    iv = os.urandom(16)
    round_keys = key_expansion(key, STD_SBOX)
    prev_block = iv
    ct = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = bytes([block[j] ^ prev_block[j] for j in range(16)])
        enc_block = std_aes_encrypt_block(xored, round_keys)
        ct += enc_block
        prev_block = enc_block
    return ct

def pad(data, block_size): 
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

# --- BENCHMARK FUNCTIONS ---
def test_standard_aes(key, plaintext, iterations=1000):
    start = time.perf_counter()
    for _ in range(iterations):
        std_aes_cbc_encrypt(plaintext, key)
    return ((time.perf_counter() - start) / iterations) * 1000

def test_dynamic_aes_with_gen(key, plaintext, iterations=1000):
    start = time.perf_counter()
    for _ in range(iterations):
        encrypt_cbc(plaintext, key)
    return ((time.perf_counter() - start) / iterations) * 1000

def test_dynamic_aes_no_gen(key, plaintext, iterations=1000):
    sbox = generate_dynamic_sbox(key)
    xor_table = generate_dynamic_xor_table(key)
    round_keys = key_expansion(key, sbox)
    padded = pad(plaintext, 16)
    
    start = time.perf_counter()
    for _ in range(iterations):
        iv = os.urandom(16)
        prev_block = iv
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes([block[j] ^ prev_block[j] for j in range(16)])
            prev_block = aes_encrypt_block(xored, round_keys, sbox, xor_table)
    return ((time.perf_counter() - start) / iterations) * 1000

if __name__ == "__main__":
    key = b'0123456789abcdef'
    plaintext = b'This is a 16-byte' 
    
    print("Running FAIR benchmarks (Pure Python)...")
    
    std_enc = test_standard_aes(key, plaintext)
    dyn_gen_enc = test_dynamic_aes_with_gen(key, plaintext)
    dyn_nogen_enc = test_dynamic_aes_no_gen(key, plaintext)
    
    print("\n=== Performance Table (Pure Python) ===")
    print("| Operation Type | Encryption Time (ms) |")
    print("| :--- | :--- |")
    print(f"| Standard AES (Pure Python) | {std_enc:.4f} |")
    print(f"| Dynamic AES (With Table Gen) | {dyn_gen_enc:.4f} |")
    print(f"| Dynamic AES (No Table Gen) | {dyn_nogen_enc:.4f} |")