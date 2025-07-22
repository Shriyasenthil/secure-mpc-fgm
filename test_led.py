import labhe
from gmpy2 import mpz
from util_fpv import fp_encode, fp_decode

lf = 32
usk = [1234]
pubkey, privkey = labhe.generate_LabHE_keypair(usk, n_length=512)

# Test values
plaintext = 3.1415
label = "test_label"

# Encode to fixed-point
x_fp = fp_encode(plaintext, lf)

# Generate secret
secret = pubkey.offline_gen_secret(label, usk[0])

# Encrypt with label
enc_labhe = pubkey.encrypt_with_label(x_fp, secret)

# Decrypt
decrypted_fp = privkey.decrypt(enc_labhe, secret)
decrypted_val = fp_decode(decrypted_fp, lf)

# Print results
print("Original:", plaintext)
print("Decrypted:", decrypted_val)
print("Difference:", abs(decrypted_val - plaintext))

assert abs(decrypted_val - plaintext) < 1e-3, " LabHE encrypt/decrypt failed!"
print(" LabHE encrypt/decrypt passed.")
