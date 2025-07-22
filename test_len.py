import labhe
from util_fpv import fp_encode, fp_decode
from gmpy2 import mpz
import random

def test_lab_encrypted_number():
    print(" Generating LabHE keypair...")
    lf = 32  # Fixed-point scaling factor
    usk = [random.randint(1, 100000)]
    pubkey, privkey = labhe.generate_LabHE_keypair(usk, n_length=512)

    # Inputs
    plaintext = 3.0
    scalar = 2.5
    expected = plaintext * scalar

    # Fixed-point encoding
    pt_fp = fp_encode(plaintext, lf)
    sc_fp = fp_encode(scalar, lf)
    print(" Plaintext (fp):", pt_fp)
    print(" Scalar (fp):", sc_fp)

    # LabHE encryption using label
    label = "demo_label"
    secret = pubkey.offline_gen_secret(label, usk[0])
    lab_enc = pubkey.encrypt_with_label(pt_fp, secret)
    print(" Encrypted:", lab_enc.ciphertext)

    # Multiply with fixed-point scalar
    result_enc = lab_enc * sc_fp
    print(" After scalar multiplication:", result_enc.ciphertext)

    # Decrypt and decode
    decrypted_fp = privkey.decrypt(result_enc, secret=secret)
    decoded_result = fp_decode(decrypted_fp, 4 * lf)  # Correct fixed-point decoding
    print(" Expected:", expected)
    print(" Decrypted decoded result:", decoded_result)
    print(" Difference:", abs(decoded_result - expected))

    # Assertion
    assert abs(decoded_result - expected) < 1e-3, " LabEncryptedNumber test failed!"
    print(" LabEncryptedNumber test passed!")

if __name__ == "__main__":
    test_lab_encrypted_number()
