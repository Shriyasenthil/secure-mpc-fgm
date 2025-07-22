import labhe
from util_fpv import fp_encode, fp_decode
from gmpy2 import mpz

lf = 32
plaintext = 3.1415
scalar = 2.5

#  encode the plaintext to fixed-point
pt_fp = fp_encode(plaintext, lf)
sc_scaled = int(scalar) 

print(f"=== Detailed Analysis ===")
print(f"pt_fp: {pt_fp}")
print(f"sc_scaled: {sc_scaled}")
print(f"Expected result (raw): {pt_fp * sc_scaled}")
print(f"Expected result (decoded): {fp_decode(pt_fp * sc_scaled, lf)}")

# Keygen
usk = [1234]
pubkey, privkey = labhe.generate_LabHE_keypair(usk, n_length=512)
label = "scalar_test"
secret = pubkey.offline_gen_secret(label, usk[0])

print(f"\n Key Analysis ")
print(f"n: {pubkey.n}")
print(f"n (hex): {hex(pubkey.n)}")
print(f"max_int: {pubkey.max_int}")
print(f"nsquare: {pubkey.nsquare}")

# Encrypt the fixed-point plaintext
enc_labhe = pubkey.encrypt_with_label(pt_fp, secret)
c0, c1_obj = enc_labhe.ciphertext

print(f"\nCiphertext Analysis")
print(f"c0: {c0}")
print(f"c0 (hex): {hex(c0)}")
print(f"c1_obj type: {type(c1_obj)}")
print(f"c1_obj: {c1_obj}")

# Test scalar multiplication using LabHE method
print(f"\n Testing _mul_scalar ")
enc_scaled = enc_labhe._mul_scalar(sc_scaled)
scaled_c0, scaled_c1_obj = enc_scaled.ciphertext

print(f"Result c0: {scaled_c0}")
print(f"Result c1_obj: {scaled_c1_obj}")

# Decrypt the result
decrypted_fp = privkey.decrypt(enc_scaled, secret=secret)
decoded_result = fp_decode(decrypted_fp, lf)

print(f"\n Final Decryption ")
print(f"Decrypted raw: {decrypted_fp}")
print(f"Decoded result: {decoded_result}")
print(f"Expected decoded: {plaintext * scalar}")

# Check correctness
assert abs(decoded_result - (plaintext * scalar)) < 1e-3, " Scalar multiplication failed"
print(" Scalar multiplication test passed.")
