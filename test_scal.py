import labhe
from gmpy2 import mpz

# Initialize keys
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

lf = 16
scale = 1 << lf
double_scale = scale * scale

plaintext = 1.0
scalar = 1.1
label = "test"

# Encrypt original value
ct = labhe.encrypt(plaintext, label, lf=lf)

# Encrypt scalar
scalar_ct = labhe.encrypt(scalar, label + "_scalar", lf=lf)

# Homomorphic multiplication (ciphertext * ciphertext)
if hasattr(labhe, "Eval_mult"):
    mult_ct = labhe.Eval_mult(pubkey, ct, scalar_ct)
    raw_mult = labhe.D(privkey, mult_ct)
    result_mult = float(raw_mult) / double_scale
    print(f"Using Eval_mult: {result_mult:.6f} (Expected: ~{plaintext * scalar})")
else:
    print("❌ labhe does not support Eval_mult (ciphertext × ciphertext).")
