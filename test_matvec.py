# test_matvec.py
import numpy as np
import labhe
from utils import he_matvec_mul_precise

lf = 16
privkey, pubkey = labhe.Init(2048)
labhe.privkey = privkey
labhe.pubkey = pubkey

# Test with simple values
test_vec = [1.0, 2.0]
I = np.eye(2)

enc_vec = [labhe.encrypt(x, f"test_{i}", lf) for i, x in enumerate(test_vec)]
result_enc = he_matvec_mul_precise(I, enc_vec, pubkey, lf)
result_dec = [labhe.decrypt(privkey, ct, lf) for ct in result_enc]

print(f"Input: {test_vec}")
print(f"Output: {result_dec}")
print(f"Should be equal: {np.allclose(test_vec, result_dec, rtol=1e-2)}")