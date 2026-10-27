# ============================================
# DYNAMIC AES-128 ENCRYPTION (CBC MODE)
# Uses: Dynamic S-Box + Dynamic XOR Table
# Input  : Key + Plaintext
# Output : IV + Ciphertext
# ============================================

from Crypto.Util.Padding import pad
import os

# ---------- STEP 1: RC4 KEY SCHEDULING ALGORITHM ----------
def rc4_ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

# ---------- STEP 2: LOGISTIC CHAOTIC MAP ----------
def logistic_chaos(seed, r=3.9, n=256):
    x = seed
    values = []
    for _ in range(n):
        x = r * x * (1 - x)
        values.append(x)
    return values

# ---------- STEP 3: GENERATE DYNAMIC S-BOX ----------
def generate_dynamic_sbox(key):
    base = rc4_ksa(key)
    seed = int.from_bytes(key[:8], 'big') / (2**64 - 1)
    chaos = logistic_chaos(seed, r=3.9, n=256)
    order = sorted(range(256), key=lambda i: chaos[i])
    dynamic_sbox = [base[i] for i in order]
    return dynamic_sbox

# ---------- STEP 4: SIMPLE PRNG (LCG) ----------
def lcg(seed):
    a = 1103515245
    c = 12345
    m = 2**31
    while True:
        seed = (a * seed + c) % m
        yield seed

# ---------- STEP 5: FISHER-YATES SHUFFLE ----------
def fisher_yates(seed, size=16):
    prng = lcg(seed)
    arr = list(range(size))
    for i in range(size - 1, 0, -1):
        j = next(prng) % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return arr

# ---------- STEP 6: GENERATE DYNAMIC XOR TABLE ----------
def generate_dynamic_xor_table(key):
    seed1 = int.from_bytes(key[:8], 'big') % (2**31 - 1)
    seed2 = int.from_bytes(key[8:16], 'big') % (2**31 - 1)
    P1 = fisher_yates(seed1, 16)
    P2 = fisher_yates(seed2, 16)
    table = [[P1[r] ^ P2[c] for c in range(16)] for r in range(16)]
    return table

# ---------- STEP 7: STANDARD AES KEY SCHEDULE ----------
def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word, sbox):
    return [sbox[b] for b in word]

def rcon(i):
    return [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36][i-1] if 1 <= i <= 10 else 0

def key_expansion(key, sbox):
    Nk, Nr = 4, 10
    w = []
    for i in range(Nk):
        w.append(list(key[4*i:4*i+4]))
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1][:]
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp, sbox)
            temp[0] ^= rcon(i//Nk)
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(Nr+1):
        key_mat = [[0]*4 for _ in range(4)]
        for col in range(4):
            word = w[4*r + col]
            for row in range(4):
                key_mat[row][col] = word[row]
        round_keys.append(key_mat)
    return round_keys

# ---------- STEP 8: AES CORE TRANSFORMATIONS ----------
def sub_bytes(state, sbox):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def xtime(a):
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return (a << 1) & 0xff

def mix_column(col):
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)

def mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        mix_column(col)
        for j in range(4):
            state[j][i] = col[j]

# ---------- STEP 9: DYNAMIC ADD ROUND KEY ----------
def add_round_key(state, round_key, xor_table):
    for i in range(4):
        for j in range(4):
            val = state[i][j]
            key_byte = round_key[i][j]
            hi = (val >> 4) & 0x0F
            lo = val & 0x0F
            khi = (key_byte >> 4) & 0x0F
            klo = key_byte & 0x0F
            new_hi = xor_table[hi][khi]
            new_lo = xor_table[lo][klo]
            state[i][j] = (new_hi << 4) | new_lo

# ---------- STEP 10: ENCRYPT ONE BLOCK ----------
def aes_encrypt_block(plaintext_block, round_keys, sbox, xor_table):
    state = [[plaintext_block[j*4 + i] for j in range(4)] for i in range(4)]
    add_round_key(state, round_keys[0], xor_table)
    for rnd in range(1, 10):
        sub_bytes(state, sbox)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd], xor_table)
    sub_bytes(state, sbox)
    shift_rows(state)
    add_round_key(state, round_keys[10], xor_table)
    return bytes([state[j][i] for i in range(4) for j in range(4)])

# ---------- STEP 11: CBC ENCRYPTION ----------
def encrypt_cbc(plaintext, key):
    sbox = generate_dynamic_sbox(key)
    xor_table = generate_dynamic_xor_table(key)
    round_keys = key_expansion(key, sbox)
    
    iv = os.urandom(16)
    padded = pad(plaintext, 16)
    
    ciphertext = iv
    prev_block = iv
    
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = bytes([block[j] ^ prev_block[j] for j in range(16)])
        enc_block = aes_encrypt_block(xored, round_keys, sbox, xor_table)
        ciphertext += enc_block
        prev_block = enc_block
    
    return ciphertext

# ---------- MAIN ----------
if __name__ == "__main__":
    
    # ---------- INPUTS ----------
    key = b'0123456789abcdef'
    plaintext = b'Hello, this is a secret message.'
    
    # ---------- ENCRYPT ----------
    full = encrypt_cbc(plaintext, key)
    iv = full[:16]
    ct = full[16:]
    
    # ---------- OUTPUT ----------
    print("IV (hex):         ", iv.hex())
    print("Ciphertext (hex): ", ct.hex())