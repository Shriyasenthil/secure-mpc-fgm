import labhe
from gmpy2 import mpz
from util_fpv import fp_encode, fp_decode  # Your fixed-point encoding/decoding

lf = 32  # Fixed-point scaling factor

# Step 1: Generate LabHE keys
usk = [1234]
pubkey, privkey = labhe.generate_LabHE_keypair(usk, n_length=512)

# Step 2: Plaintext and scalar (floating-point)
float_val = 3.1415
scalar = 2.5

# Step 3: Encode both to fixed-point
x_fp = fp_encode(float_val, lf)
s_fp = fp_encode(scalar, lf)

# Step 4: Encrypt plaintext
label = "test_labhe_scalar"
secret = pubkey.offline_gen_secret(label, usk[0])
lf = 32  # fixed-point scaling factor
p = 1.23  # your original float
p_fp = int(p * (1 << lf))  # fixed-point encode p

enc = pubkey.Pai_key.encrypt(p_fp)
enc_scaled = enc * s_fp  # This works


# Step 6: Decrypt and decode the result
decrypted = privkey.decrypt(enc_scaled, secret=secret)
result = fp_decode(decrypted, 2 * lf)  # Adjust for double scaling

# Step 7: Print and compare
expected = float_val * scalar
print("Original:", float_val)
print("Scalar:", scalar)
print("Expected:", expected)
print("Decrypted:", result)

assert abs(result - expected) < 1e-3, "❌ Fixed-point scalar multiplication failed!"
print("✅ Fixed-point scalar multiplication passed.")
