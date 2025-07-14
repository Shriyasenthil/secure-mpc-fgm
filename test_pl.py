#!/usr/bin/env python3

from paillier import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
from labhe import LabEncryptedNumber, LabHEPublicKey, LabHEPrivateKey
from util_fpv import fp_encode, fp_decode, encrypt_vector
from gmpy2 import mpz
import random

DEFAULT_KEYSIZE = 512
lf = 32  # Fixed-point scale factor

def generate_keys():
    # Simulate key setup
    p = mpz('10668181328669357029')
    q = mpz('10668181328669357051')
    pub = PaillierPublicKey(n=p * q)
    priv = PaillierPrivateKey(pub, p, q)
    lab_pub = LabHEPublicKey(pub)
    usk = [random.randint(1, 100) for _ in range(5)]
    upk = encrypt_vector(pub, usk)
    lab_priv = LabHEPrivateKey(priv, upk)
    return lab_pub, lab_priv, usk

def main():
    lab_pub, lab_priv, usk = generate_keys()
    print("🔐 Public and private keys ready")

    # Input
    plaintext = 3.1415
    scalar = 2.5
    print(f"Original: {plaintext}")
    print(f"Scalar: {scalar}")

    # Encode both inputs as fixed-point integers
    pt_fp = fp_encode(plaintext, lf)
    scalar_fp = int(scalar * (2 ** lf))
    print(f"Fixed-point encoded pt: {pt_fp}")
    print(f"Fixed-point encoded scalar: {scalar_fp}")

    # Encrypt plaintext (pt_fp)
    c0 = lab_pub.Pai_key.encrypt(pt_fp).ciphertext()
    print(f"Original ciphertext: {c0}")

    # Multiply encrypted plaintext with fixed-point scalar
    paillier_encrypted = EncryptedNumber(lab_pub.Pai_key, c0)
    paillier_scaled = paillier_encrypted * scalar_fp
    result_ciphertext = paillier_scaled.ciphertext()
    print(f"Result of scalar multiplication: {result_ciphertext}")

    # Relabel as LabHE ciphertext (dummy label)
    relabeled = LabEncryptedNumber(lab_pub, (result_ciphertext, 0))
    print(f"Relabeled ciphertext: {relabeled.ciphertext}")

    # Decrypt
    secret = lab_pub.offline_gen_secret("dummy", usk[0])
    final_value = lab_priv.decrypt(relabeled, secret=secret)
    print(f"🔓 Final decrypted value: {final_value}")

    # Decode with 2 * lf due to both inputs being scaled
    decoded = fp_decode(final_value, 2 * lf)
    print(f"✅ Decoded final result: {decoded}")

    # Check correctness
    expected = plaintext * scalar
    print(f"Expected: {expected}")
    print(f"Difference: {abs(decoded - expected)}")
    assert abs(decoded - expected) < 1e-3, "❌ Scalar multiplication failed!"

if __name__ == '__main__':
    main()
