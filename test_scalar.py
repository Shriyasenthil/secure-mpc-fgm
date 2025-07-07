import labhe
from utils import encode_scalar
from gmpy2 import mpz

# Initialize keys
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

lf = 16  # Fixed-point scaling factor

# Encrypt a test value (1.0)
plaintext = 1.0
label = "test"
ct = labhe.encrypt(plaintext, label, lf=lf)

# Encode scalar 1.1 and multiply
scalar = 1.1
encoded_scalar = encode_scalar(scalar, lf)
scaled_ct = labhe.Eval_mult_scalar(pubkey, ct, encoded_scalar)

# Decrypt result
decrypted = labhe.decrypt(privkey, scaled_ct, lf)

print(f"{plaintext} * {scalar} = {decrypted:.6f} (Expected: ~{plaintext * scalar})")
