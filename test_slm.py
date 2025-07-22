import labhe
from util_fpv import fp_encode, fp_decode
from gmpy2 import mpz

lf = 32  

# Step 1: Generate LabHE keys
usk = [1234]
pubkey, privkey = labhe.generate_LabHE_keypair(usk, n_length=512)

# Step 2: Define plaintext and scalar
plaintext = 3.1415
scalar = 2.5

# Step 3: Fixed-point encode
pt_fp = fp_encode(plaintext, lf)
sc_fp = fp_encode(scalar, lf)

# Encrypt using plain Paillier
enc = pubkey.Pai_key.encrypt(pt_fp)     
enc_scaled = enc * sc_fp                

# Step 5: Decrypt
decrypted_fp = privkey.msk.decrypt(enc_scaled)

# Step 6: Decode result
result = fp_decode(decrypted_fp, 2 * lf)  # 2*lf because both inputs were scaled

# Step 7: Display
expected = plaintext * scalar
print("Original:", plaintext)
print("Scalar:", scalar)
print("Expected:", expected)
print("Decrypted:", result)
print("Difference:", abs(result - expected))

# Step 8: Assert correctness
assert abs(result - expected) < 1e-3, " Scalar multiplication failed!"
print(" Scalar multiplication test passed.")
