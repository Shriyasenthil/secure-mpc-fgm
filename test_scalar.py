import labhe
from gmpy2 import mpz

def Eval_mult_scalar_fixed(pub, ct, scalar_float, lf, debug=False):
    """Fixed-point scalar multiplication for homomorphic encryption"""
    scale = 1 << lf
    scalar_fixed = int(round(scalar_float * scale))
    
    if debug:
        print(f"[Eval_mult_scalar_fixed] Float: {scalar_float}, Fixed: {scalar_fixed}")
    
    # Use the original function with the properly scaled scalar
    return labhe.Eval_mult_scalar(pub, ct, mpz(scalar_fixed), debug)

# Initialize keys (only once)
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

lf = 16
scale = 1 << lf  # 2^16 = 65536
double_scale = scale * scale  # 2^32

# Encrypt value
plaintext = 1.0
label = "test"
ct = labhe.encrypt(plaintext, label, lf=lf)

# Debug: Check what the encrypted 1.0 decrypts to
raw_original = labhe.D(privkey, ct)
print(f"Original encrypted 1.0 decrypts to: {raw_original}")
print(f"Original as float: {float(raw_original) / scale}")

# Test scalar multiplication
scalar = 1.1
print(f"Encoded scalar: {int(round(scalar * scale))} (should be ~{int(1.1 * 65536)})")

# Use the corrected function
scaled_ct = Eval_mult_scalar_fixed(pubkey, ct, scalar, lf, debug=True)
raw = labhe.D(privkey, scaled_ct)
result = float(raw) / double_scale

print(f"{plaintext} * {scalar} = {result:.6f} (Expected: ~{plaintext * scalar})")