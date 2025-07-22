import labhe
from gmpy2 import mpz
from util_fpv import fp_encode, fp_decode

lf = 32  

# Step 1: Generate LabHE keys (internally generates Paillier keys)
usk = [1234]
pubkey, privkey = labhe.generate_LabHE_keypair(usk, n_length=512)

# Step 2: Encode plaintext and scalar to fixed point
float_val = 3.1415
scalar = 2.5
x_fp = fp_encode(float_val, lf)
s_fp = fp_encode(scalar, lf)

# Step 3: Encrypt using Paillier
enc = pubkey.Pai_key.encrypt(x_fp)

# Step 4: Multiply homomorphically
enc_scaled = enc * s_fp  # Paillier supports scalar mul directly

# Step 5: Decrypt using Paillier
decrypted_fp = privkey.msk.decrypt(enc_scaled)

# Step 6: Decode (adjust lf for double scaling)
result = fp_decode(decrypted_fp, 2 * lf)

# Step 7: Verify
print("Original:", float_val)
print("Scalar:", scalar)
print("Expected:", float_val * scalar)
print("Decrypted:", result)

assert abs(result - (float_val * scalar)) < 1e-3, " Scalar multiplication failed!"
print(" Scalar multiplication passed.")
