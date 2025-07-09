import labhe
from gmpy2 import mpz

# Test with the fixed decryption
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

lf = 16
scale = 1 << lf
double_scale = scale * scale

plaintext = 1.0
label = "test"
ct = labhe.encrypt(plaintext, label, lf=lf)

print("=== TESTING FIXED DECRYPTION ===")

# Test scalar multiplication
scalar = 1.1
encoded_scalar = int(round(scalar * scale))  # 72090
scaled_ct = labhe.Eval_mult_scalar(pubkey, ct, mpz(encoded_scalar))

# Use the fixed decryption with scalar parameter
raw = labhe.D(privkey, scaled_ct, encoded_scalar)
result = float(raw) / double_scale

print(f"1.0 * 1.1 = {result:.6f} (Expected: ~{plaintext * scalar})")

# Verify with scalar = 2 for easier checking
scaled_ct_2 = labhe.Eval_mult_scalar(pubkey, ct, mpz(2))
raw_2 = labhe.D(privkey, scaled_ct_2, 2)
expected_2 = 65536 * 2
print(f"Scalar=2: {raw_2} (Expected: {expected_2})")
print(f"2x test: {float(raw_2) / scale:.6f} (Expected: ~2.0)")

# Test with original decryption (should be wrong)
raw_wrong = labhe.D(privkey, scaled_ct_2)  # No scalar parameter
print(f"Wrong decryption: {raw_wrong} (should be huge number)")
