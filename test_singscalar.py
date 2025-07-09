import labhe
from gmpy2 import mpz

# Initialize keys
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

lf = 16
scale = 1 << lf  # 2^16 = 65536
double_scale = scale * scale  # 2^32 = 4294967296

# Encrypt value
plaintext = 1.0
label = "test"
ct = labhe.encrypt(plaintext, label, lf=lf)

# Test scalar multiplication by 2.0
scalar_2 = 2.0
encoded_scalar_2 = int(round(scalar_2 * scale))  # e.g., 2.0 * 65536 = 131072
# Use the corrected function
scaled_ct = labhe.Eval_mult_scalar_fixed(pubkey, ct, scalar, lf)
raw = labhe.D(privkey, scaled_ct)
result = float(raw) / double_scale  # Still divide by 2^32

print(f"1.0 * 2.0 = {result_2:.6f} (Expected: ~2.0)")
