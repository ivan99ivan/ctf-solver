import subprocess
import sys
import os
import hashlib
import binascii
import time

# --- Configuration ---
ITERATIONS = 10_000_000_000
N_STR = "13574622588888049690561023638430199046729771972426419368439382361956704632424371160900330651985202981344914041234519924584183091503321246746925820669936859914537956430459499249317359251094723909981666168094204351889589504402255395865166811065791794058730419139155749660535793739465836481175376131804092870530232574336824833752086034916770433965625573677682963744365751633866904267066661256666248770025722245555263888911687959268196636333490874023930576033436225517461588419316874364224451944571886285286449021999692833508952695809827607992963395440895127166093103869949337272970805338156064336941758567461421224837121"
NONCE_HEX = "044e21c90aeb8f986bc2dddf"
CT_HEX = "1866e54a807e729bfbe60f5ab55101e1c6f61e7121a543b4595aae515fee8c4c"
TAG_HEX = "a2fa18a96cf1928191524d9bda0c07b3"

# --- Import Crypto Library ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Installing cryptography...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def compile_cpp():
    """Writes and compiles the high-performance C++ solver."""
    cpp_code = r"""
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <chrono>

#pragma GCC optimize ("Ofast,unroll-loops")
#pragma GCC target ("avx2,bmi,bmi2,lzcnt,popcnt")

typedef unsigned __int128 uint128_t;

// Hardcoded N limbs (Little Endian 64-bit)
uint64_t N[32] = {
    0xDCC1C2CD38104001ULL, 0x892236EBA1F520F3ULL, 0x246063FB58ECBA69ULL, 0xD8A8093E4C1025D3ULL, 
    0x4E0646FCB38E9343ULL, 0xDDD31FE7ED1A8C8CULL, 0xD9C677DE72456538ULL, 0xC27D6684CAC59E32ULL, 
    0x0BB247EC547A5A33ULL, 0x7E015CD84CC9F9DFULL, 0x441C394A3FA9B327ULL, 0xCBD08CCB38432C35ULL, 
    0x5A5BD40AC0BBA041ULL, 0xB3CA76C16AFA1C28ULL, 0x945BE237755DAD56ULL, 0xD63C69D0D7BBFADDULL, 
    0x4617C78CDB3BDC3CULL, 0xC19F9B5DF4F73EEEULL, 0x094374FDE74C8DB2ULL, 0xB48D86898153C397ULL, 
    0xF22C9C85B79231C2ULL, 0x37FF6937E57F139FULL, 0xAE4CDD23D251DBE2ULL, 0x44CD636D433D4763ULL, 
    0x30BC13511BA6119BULL, 0xF75996AF219698DDULL, 0x88E736C73AA4FC82ULL, 0x489580F40F6B7E2FULL, 
    0xC9B4D192132210EFULL, 0xF7696BC40D4C20EAULL, 0xF0B10F1FD78F63AAULL, 0x6B881F1332AD1A23ULL
};

// R2 = 2^4096 mod N
uint64_t R2[32] = {
    0x99DFFCD0BAA733DBULL, 0x8DEEDF3014BFAB73ULL, 0x2380ACBE044F634AULL, 0xE03950085BAAA914ULL, 
    0xD923EE33647C250AULL, 0xCF8E97E2197C8BACULL, 0x8207879908F1C786ULL, 0x9893D486351F253AULL, 
    0xB797D35068B3E079ULL, 0xF1F09BE584A08CEAULL, 0x5D14D81080CF948AULL, 0x09C338E1E845F430ULL, 
    0xF46B745295989A0EULL, 0xDB134D58DEB5018BULL, 0xA0A3295986B3CAFFULL, 0x090652B1C3FB851FULL, 
    0x5437F0226E76E7D2ULL, 0xB46040A675E887B0ULL, 0xEC099E6C1935D0EEULL, 0xBD052AB8060F2057ULL, 
    0x4FA2104900DBA4B1ULL, 0xE3ABDC08FB782F9DULL, 0x55C446AE81907B3DULL, 0x491022556B7AAACDULL, 
    0xF22979E71D95D08CULL, 0x45F6B68D63357ACDULL, 0x27F54800804D15D6ULL, 0x8E137F99B28DF1F3ULL, 
    0x718B57F0B50610E5ULL, 0x4628DD055F8527A5ULL, 0x44F615A7246F8E8BULL, 0x1291723C6DE20C33ULL
};

uint64_t N_prime = 0xAFB729C528103FFFULL;

inline void mul_mont(const uint64_t a[32], const uint64_t b[32], uint64_t out[32]) {
    uint64_t T[65] = {0};
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint128_t carry = 0;
        #pragma GCC unroll 32
        for (int j = 0; j < 32; j++) {
            carry += (uint128_t)a[i] * b[j] + T[i + j];
            T[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        uint128_t sum = (uint128_t)T[i + 32] + carry;
        T[i + 32] = (uint64_t)sum;
        T[i + 33] += (uint64_t)(sum >> 64);
    }
    
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint64_t m = T[i] * N_prime;
        uint128_t carry = 0;
        #pragma GCC unroll 32
        for (int j = 0; j < 32; j++) {
            carry += T[i + j] + (uint128_t)m * N[j];
            T[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        uint128_t sum = (uint128_t)T[i + 32] + carry;
        T[i + 32] = (uint64_t)sum;
        T[i + 33] += (uint64_t)(sum >> 64);
    }
    
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) out[i] = T[i + 32];
    
    bool borrow = false;
    uint64_t temp[32];
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint128_t diff = (uint128_t)out[i] - N[i] - borrow;
        temp[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }
    if (!borrow) {
        #pragma GCC unroll 32
        for (int i = 0; i < 32; i++) out[i] = temp[i];
    }
}

inline void square_mont(const uint64_t a[32], uint64_t out[32]) {
    uint64_t T[65] = {0};
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint128_t carry = 0;
        uint128_t a_i = a[i];
        #pragma GCC unroll 32
        for (int j = i + 1; j < 32; j++) {
            carry += a_i * a[j] + T[i + j];
            T[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        uint128_t sum = (uint128_t)T[i + 32] + carry;
        T[i + 32] = (uint64_t)sum;
        T[i + 33] += (uint64_t)(sum >> 64);
    }
    
    uint128_t carry2 = 0;
    #pragma GCC unroll 64
    for (int i = 1; i < 64; i++) {
        uint128_t val = ((uint128_t)T[i] << 1) + carry2;
        T[i] = (uint64_t)val;
        carry2 = val >> 64;
    }
    T[64] += (uint64_t)carry2;
    
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint128_t sq = (uint128_t)a[i] * a[i];
        uint128_t sum = (uint128_t)T[2 * i] + (uint64_t)sq;
        T[2 * i] = (uint64_t)sum;
        uint128_t c = (sum >> 64) + (sq >> 64);
        
        int k = 2 * i + 1;
        while (c > 0 && k < 65) {
            sum = (uint128_t)T[k] + c;
            T[k] = (uint64_t)sum;
            c = sum >> 64;
            k++;
        }
    }
    
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint64_t m = T[i] * N_prime;
        uint128_t carry = 0;
        #pragma GCC unroll 32
        for (int j = 0; j < 32; j++) {
            carry += T[i + j] + (uint128_t)m * N[j];
            T[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        uint128_t sum = (uint128_t)T[i + 32] + carry;
        T[i + 32] = (uint64_t)sum;
        T[i + 33] += (uint64_t)(sum >> 64);
    }
    
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) out[i] = T[i + 32];
    
    bool borrow = false;
    uint64_t temp[32];
    #pragma GCC unroll 32
    for (int i = 0; i < 32; i++) {
        uint128_t diff = (uint128_t)out[i] - N[i] - borrow;
        temp[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }
    if (!borrow) {
        #pragma GCC unroll 32
        for (int i = 0; i < 32; i++) out[i] = temp[i];
    }
}

int main() {
    uint64_t x[32] = {0};
    x[0] = 2;
    
    uint64_t x_mont[32];
    mul_mont(x, R2, x_mont);
    
    long long iters = ITERATIONS_VAL; // Replaced by Python
    auto start = std::chrono::high_resolution_clock::now();
    
    for (long long i = 0; i < iters; i++) {
        square_mont(x_mont, x_mont);
        // Progress logging every 100M iterations
        if (i % 100000000LL == 0 && i > 0) {
             fprintf(stderr, "Progress: %.1f%%\n", (double)i / iters * 100.0);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    fprintf(stderr, "Completed in %.2f seconds\n", diff.count());
    
    uint64_t x_norm[32];
    uint64_t one[32] = {0};
    one[0] = 1;
    mul_mont(x_mont, one, x_norm);
    
    // Output Hex String
    for(int i=31; i>=0; i--) {
        printf("%016llx", x_norm[i]);
    }
    printf("\n");
    return 0;
}
"""
    # Replace placeholder with actual iteration count
    final_cpp = cpp_code.replace("ITERATIONS_VAL", str(ITERATIONS))
    
    with open("solver.cpp", "w") as f:
        f.write(final_cpp)
        
    print("Compiling C++ solver...")
    res = subprocess.run(["g++", "-O3", "-march=native", "solver.cpp", "-o", "solver"], capture_output=True, text=True)
    if res.returncode != 0:
        raise Exception(f"Compilation failed:\n{res.stderr}")
    print("Compilation successful.")

def run_solver_binary():
    print("Running binary (this takes ~8-10 hours)...")
    # We capture stdout (the hex result) and stderr (progress logs) separately
    proc = subprocess.Popen(["./solver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Read stderr line by line to show progress in GH Actions logs
    import threading
    def read_stderr(pipe):
        for line in pipe:
            print(line.strip()) # Prints to console/log
    t = threading.Thread(target=read_stderr, args=(proc.stderr,))
    t.start()
    
    hex_str = proc.stdout.read().strip()
    proc.wait()
    t.join()
    
    if not hex_str:
        raise Exception("Solver produced no output!")
        
    print(f"Result Hex Length: {len(hex_str)}")
    return hex_str

def decrypt(hex_str):
    x_int = int(hex_str, 16)
    x_dec = str(x_int)
    
    print(f"Calculating SHA-256 of decimal string (length {len(x_dec)})...")
    key = hashlib.sha256(x_dec.encode('ascii')).digest()
    
    nonce = binascii.unhexlify(NONCE_HEX)
    ct = binascii.unhexlify(CT_HEX)
    tag = binascii.unhexlify(TAG_HEX)
    
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct + tag, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"DECRYPTION FAILED: {e}"

if __name__ == "__main__":
    compile_cpp()
    hex_result = run_solver_binary()
    answer = decrypt(hex_result)
    
    print("="*30)
    print("FINAL ANSWER:")
    print(answer)
    print("="*30)
    
    # Write to file for artifact upload
    with open("output.txt", "w") as f:
        f.write(answer)
