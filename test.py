from pathlib import Path
from termcolor import colored

try:
    # Try to import from installed package (pip)
    from dpqc import MLKEM512, MLKEM768, MLKEM1024, MLDSA44, MLDSA65, MLDSA87, Falcon512, Falcon1024
except ImportError:
    # Fallback to local import if running from source
    import sys, os
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    from dpqc import MLKEM512, MLKEM768, MLKEM1024, MLDSA44, MLDSA65, MLDSA87, Falcon512, Falcon1024

# some directories
CACHE_DIR = Path(__file__).parent / 'cache'
SAMPLES_DIR = CACHE_DIR / 'samples'
BINARY_DIR = CACHE_DIR / 'bin'

# function to write files safely
def write_file(name, contentType, content):
    print(f"    [w] Writing {contentType} for {name}...")
    exp_path = SAMPLES_DIR / name
    exp_bin_path = SAMPLES_DIR / name / 'bin'
    exp_path.mkdir(parents=True, exist_ok=True)
    exp_bin_path.mkdir(parents=True, exist_ok=True)
    # Save binary version if content is bytes
    if isinstance(content, bytes):
        bin_file = exp_bin_path / f"{contentType}.bin"
        with open(bin_file, "wb") as f:
            f.write(content)
        # Save hex version in text file
        txt_file = exp_path / f"{contentType}.txt"
        hex_content = content.hex()
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(hex_content)
    # Save only text version if content is string
    elif isinstance(content, str):
        txt_file = exp_path / f"{contentType}.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(content)

# function to make the KEM test easier
def test_kem(name, kem_class, secret_message):
    print(f"[i] Testing KEM algorithm: {name}")
    msg_file       = "message"
    pk_file        = "public_key"
    sk_file        = "secret_key"
    ct_file        = "ciphertext"
    ss1_file       = "shared_secret_1"
    ss2_file       = "shared_secret_2"
    encrypted_file = "encrypted_message"
    decrypted_file = "decrypted_message"
    write_file(name, "message", secret_message.decode())
    print(f"    [p] Starting test of {name} algorithm, creating pk,sk")
    kem = kem_class(BINARY_DIR)
    pk, sk = kem.keypair()
    write_file(name, "public_key", pk)
    write_file(name, "secret_key", sk)
    ct, ss1 = kem.encapsulate(pk)
    write_file(name, "ciphertext", ct)
    write_file(name, "shared_secret_1", ss1)
    print(f"    [i] pk length: {len(pk)}, sk length: {len(sk)}, encrypted msg length: {len(ct)}")
    ss2 = kem.decapsulate(ct, sk)
    write_file(name, "shared_secret_2", ss2)
    result = "SUCCESS" if ss1 == ss2 else "FAILED"
    print(f"    [i] Decryption result: {result} (shared secret matched: {ss1 == ss2})")
    print(f"    [p] Test of {name} algorithm ended\n")

# function to make the signature test easier
def test_signature(name, sig_class, secret_message):
    print(f"[i] Testing signature algorithm: {name}")
    # create output directory for this algorithm
    exp_path = SAMPLES_DIR / name
    exp_path.mkdir(parents=True, exist_ok=True)
    msg_file       = "message"
    pk_file        = "public_key"
    sk_file        = "secret_key"
    encrypted_file = "encrypted_message"
    decrypted_file = "decrypted_message"
    write_file(name, "message", secret_message.decode())
    try:
        print(f"    [p] Starting test of {name} algorithm, creating pk,sk")
        sig = sig_class(BINARY_DIR)
        pk, sk = sig.keypair()
        write_file(name, "public_key", pk)
        write_file(name, "secret_key", sk)
        signed = sig.sign(secret_message, sk)
        write_file(name, "encrypted_message", signed)
        print(f"    [i] pk length: {len(pk)}, sk length: {len(sk)}, signed msg length: {len(signed)}")
        verified = sig.verify(signed, pk)
        write_file(name, "decrypted_message", verified)
        result = "SUCCESS" if verified == secret_message else "FAILED"
        print(f"    [i] Verification result: {result} (message matched: {verified == secret_message})")
        print(f"    [p] Test of {name} algorithm ended\n")
    except Exception as e:
        print(f"pk length: N/A, sk length: N/A, signed msg length: N/A")
        print(f"    [p] Verification result: FAILED - {str(e)}")
        print(f"    [p] Test of {name} algorithm ended\n")

print("\n" + "#"*66)
print("[Testing available all Post-Quantum Cryptography (PQC) algorithms]".center(66))
print("    [i] info")
print("    [p] progress")
print("    [w] write")
print("-"*66)
secret_message = b"This is a secret message for PQC testing!"
print(f"    [i] message: {secret_message.decode()}")
print(f"    [i] dir: {colored(str(CACHE_DIR), 'cyan')}")
print(f"    [i] dpqc version: 0.0.1")
print("#"*66 + "\n")
test_kem("ML-KEM-512",          MLKEM512, secret_message)
test_kem("ML-KEM-768",          MLKEM768, secret_message)
test_kem("ML-KEM-1024",        MLKEM1024, secret_message)
test_signature("ML-DSA-44",      MLDSA44, secret_message)
test_signature("ML-DSA-65",      MLDSA65, secret_message)
test_signature("ML-DSA-87",      MLDSA87, secret_message)
test_signature("Falcon-512",   Falcon512, secret_message)
test_signature("Falcon-1024", Falcon1024, secret_message)
print("="*66)
print("All 8 PQC algorithms tested!")
print("="*66)