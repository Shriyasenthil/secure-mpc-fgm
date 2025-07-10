import labhe
from gmpy2 import mpz

# Initialize keys
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

lf = 16
scale = 1 << lf

# Encrypt
plaintext = 1.0
label = "test"
ct = labhe.encrypt(plaintext, label, lf=lf)

# Test with scalar = 1 
print("=== DIAGNOSTIC TEST ===")
raw_original = labhe.D(privkey, ct)
print(f"Original: {raw_original}")

scaled_ct_1 = labhe.Eval_mult_scalar(pubkey, ct, mpz(1))
raw_1 = labhe.D(privkey, scaled_ct_1)
print(f"After multiplying by 1: {raw_1}")
print(f"Should be equal: {raw_original == raw_1}")

# Test with scalar = 2
scaled_ct_2 = labhe.Eval_mult_scalar(pubkey, ct, mpz(2))
raw_2 = labhe.D(privkey, scaled_ct_2)
expected_2 = raw_original * 2
print(f"After multiplying by 2: {raw_2}")
print(f"Expected (2x original): {expected_2}")
print(f"Ratio: {float(raw_2) / float(expected_2)}")