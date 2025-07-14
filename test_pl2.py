#!/usr/bin/env python3

from paillier import PaillierPublicKey, PaillierPrivateKey
from labhe import LabEncryptedNumber, LabHEPublicKey, LabHEPrivateKey
from util_fpv import encrypt_vector
from gmpy2 import mpz
import random

def generate_keys():
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

    # Use raw integers
    plaintext = 42
    scalar = 3
    print(f"Plaintext: {plaintext}")
    print(f"Scalar: {scalar}")

    # Encrypt the value with a dummy label
    label = "dummy"
    secret = lab_pub.offline_gen_secret(label, usk[0])
    lab_enc = lab_pub.encrypt_with_label(plaintext, secret)
    print(f"🔐 Encrypted ciphertext: {lab_enc.ciphertext}")

    # Multiply with scalar using LabHE
    result = lab_enc * scalar
    print(f"🧮 After scalar multiplication: {result.ciphertext}")

    # Decrypt the result
    decrypted = lab_priv.decrypt(result, secret=secret)
    print(f"✅ Decrypted result: {decrypted}")

    # Check correctness
    expected = plaintext * scalar
    print(f"Expected: {expected}")
    assert decrypted == expected, "❌ Multiplication result incorrect!"

if __name__ == '__main__':
    main()
