from gmpy2 import mpz, invert
import numpy as np
import labhe


def fp_vector(vec, lf=16):
    scale = 1 << lf
    return [int(round(v * scale)) for v in vec]


def encrypt_vector(vector, pubkey, lf=16):
    encoded = fp_vector(vector, lf)
    return [labhe.E(pubkey, None, f"enc_{i}", val) for i, val in enumerate(encoded)]


def decrypt_vector(enc_vec, privkey, lf=16):
    return [labhe.D(privkey, c) / (1 << lf) for c in enc_vec]


def zero_vector(n, pubkey, lf=16):
    return [labhe.encrypt(0.0, label=f"z_{i}", lf=lf) for i in range(n)]


def he_add(pubkey, enc_vec1, enc_vec2):
    return [labhe.Eval_add(pubkey, a, b) for a, b in zip(enc_vec1, enc_vec2)]


def he_scalar_mul(pubkey, enc_vec, scalar, lf=16):
    encoded_scalar = int(round(scalar * (1 << lf)))
    return [labhe.Eval_mult_scalar(pubkey, c, mpz(encoded_scalar)) for c in enc_vec]


def he_matvec_mul_precise(mat, enc_vec, pubkey, lf=16):
    from labhe import decrypt
    from utils import fp_vector
    print("\n🔍 [he_matvec_mul_precise] Called with matrix:")
    print(np.array(mat))
    print("🔍 Encrypted input vector:")
    for i, ct in enumerate(enc_vec):
        try:
            val = decrypt(labhe.privkey, ct, lf)
            print(f"  enc_vec[{i}] = {val:.4f}")
        except Exception as e:
            print(f"  ⚠️ Failed to decrypt enc_vec[{i}]: {e}")

    result = []
    scale = 1 << lf
    inv_scale = invert(scale, pubkey.n)

    for i, row in enumerate(mat):
        acc = None
        for j, scalar in enumerate(row):
            if abs(scalar) < 1e-10:
                continue
            encoded_scalar = int(round(scalar))
            print(f"  → row[{i}][{j}] = {scalar} → encoded: {encoded_scalar}")
            prod = labhe.Eval_mult_scalar(pubkey, enc_vec[j], mpz(encoded_scalar))
            prod.label = f"row_{i}"
            acc = prod if acc is None else labhe.Eval_add(pubkey, acc, prod)

        if acc is None:
            acc = labhe.Eval_mult_scalar(pubkey, enc_vec[0], mpz(0))
            acc.label = f"row_{i}"

        acc = labhe.Eval_mult_scalar(pubkey, acc, inv_scale)
        result.append(acc)

    print("✅ [he_matvec_mul_precise] Finished. Output is encrypted vector.")
    return result



def control_scalar_mult_fixed(pubkey, ciphertext, scalar_float, lf=16):
    encoded_scalar = int(round(scalar_float * (1 << lf)))
    return labhe.Eval_mult_scalar(pubkey, ciphertext, mpz(encoded_scalar))


def encode_scalar(val, pubkey, lf=16):
    scale = 1 << lf
    encoded = int(round(val * scale))

    max_val = pubkey.n // 2
    if abs(encoded) > max_val:
        raise ValueError(f"Value {val} too large for encoding with lf={lf}")

    if encoded < 0:
        encoded += pubkey.n

    return encoded


def truncate(value, lf=16):
    return value / (1 << lf)


def he_matvec_mul(mat, enc_vec, pubkey):
    result = []
    for i in range(mat.shape[0]):
        acc = None
        for j in range(mat.shape[1]):
            scalar = int(round(mat[i][j]))
            prod = labhe.Eval_mult_scalar(pubkey, enc_vec[j], scalar)
            acc = prod if acc is None else labhe.Eval_add(pubkey, acc, prod)
        result.append(acc)
    return result
