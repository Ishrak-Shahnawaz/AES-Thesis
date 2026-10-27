import matplotlib.pyplot as plt
import time
import os
from dynamic_aes_enc_code import generate_dynamic_sbox, generate_dynamic_xor_table, key_expansion, aes_encrypt_block

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

# --- STANDARD PYTHON AES FUNCTIONS ---
def std_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = STD_SBOX[state[i][j]]

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
        for j in range(4):
            state[j][i] = col[j]

def std_add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

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


if __name__ == "__main__":
    key = b'0123456789abcdef'
    plaintext = b'A' * 1024 # 1 KB payload
    iterations = 100

    print("Running FAIR benchmarks (Pure Python vs Pure Python)...")

    # 1. Pure Python Standard AES
    std_round_keys = key_expansion(key, STD_SBOX)
    start = time.perf_counter()
    for _ in range(iterations):
        for i in range(0, len(plaintext), 16):
            std_aes_encrypt_block(plaintext[i:i+16], std_round_keys)
    std_time = (time.perf_counter() - start) / iterations

    # 2. Pure Python Dynamic AES (With Gen)
    start = time.perf_counter()
    for _ in range(iterations):
        sbox = generate_dynamic_sbox(key)
        xor_table = generate_dynamic_xor_table(key)
        dyn_round_keys = key_expansion(key, sbox)
        for i in range(0, len(plaintext), 16):
            aes_encrypt_block(plaintext[i:i+16], dyn_round_keys, sbox, xor_table)
    dyn_gen_time = (time.perf_counter() - start) / iterations

    # 3. Pure Python Dynamic AES (No Gen)
    sbox = generate_dynamic_sbox(key)
    xor_table = generate_dynamic_xor_table(key)
    dyn_round_keys = key_expansion(key, sbox)
    start = time.perf_counter()
    for _ in range(iterations):
        for i in range(0, len(plaintext), 16):
            aes_encrypt_block(plaintext[i:i+16], dyn_round_keys, sbox, xor_table)
    dyn_nogen_time = (time.perf_counter() - start) / iterations

    # --- Convert to MB/s ---
    # 1 KB = 0.0009765625 MB
    def to_mbps(time_sec):
        return 0.0009765625 / time_sec

    std_throughput = to_mbps(std_time)
    dyn_nogen_throughput = to_mbps(dyn_nogen_time)
    dyn_gen_throughput = to_mbps(dyn_gen_time)

    # --- Draw the Chart ---
    labels = ['Standard AES\n(Pure Python)', 'Dynamic AES\n(No Table Gen)', 'Dynamic AES\n(With Table Gen)']
    throughputs = [std_throughput, dyn_nogen_throughput, dyn_gen_throughput]
    colors = ['#4CAF50', '#2196F3', '#FF9800']

    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, throughputs, color=colors, edgecolor='black', alpha=0.8)

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + (max(throughputs)*0.02), f'{yval:.3f} MB/s', 
                 ha='center', va='bottom', fontweight='bold')

    plt.title('Encryption Throughput Comparison (Pure Python)', fontsize=14, fontweight='bold')
    plt.ylabel('Throughput (MB/s)', fontsize=12)
    plt.xlabel('Cipher Type', fontsize=12)
    plt.ylim(0, max(throughputs) * 1.15)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    plt.savefig('performance_throughput_chart.png', dpi=300, bbox_inches='tight')
    print("Diagram saved as 'performance_throughput_chart.png'!")
    plt.show()