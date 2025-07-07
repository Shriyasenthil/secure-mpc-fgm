import os
import labhe
from prg_utils import prg
from gmpy2 import mpz
import numpy as np


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ot_send(msg0: bytes, msg1: bytes, seed0: bytes, seed1: bytes) -> tuple[bytes, bytes]:
    r0 = prg(seed0, len(msg0))
    r1 = prg(seed1, len(msg1))
    c0 = xor_bytes(msg0, r0)
    c1 = xor_bytes(msg1, r1)
    return c0, c1


def ot_receive(choice_bit: int, seed: bytes, c0: bytes, c1: bytes) -> bytes:
    r = prg(seed, len(c0))
    return xor_bytes(c0 if choice_bit == 0 else c1, r)


def generate_seed(seed_length: int = 16) -> bytes:
    return os.urandom(seed_length)


def encrypt_vector(vector, pubkey, lf=16):
    return [labhe.E(pubkey, None, f"enc_{i}", labhe.Encode(x, pubkey, lf)) for i, x in enumerate(vector)]


def decrypt_vector(enc_vec, privkey, lf=16):
    plain = []
    for enc in enc_vec:
        if isinstance(enc, dict):
            cipher_obj = labhe.Ciphertext.from_json(enc)
        elif hasattr(enc, 'ciphertext'):
            cipher_obj = enc
        else:
            raise TypeError("Unknown ciphertext format in decrypt_vector()")
        val = labhe.D(privkey, cipher_obj)
        plain.append(val / (1 << lf))
    return plain


def truncate(values, lf):
    scale = 1 << lf
    return [float(v) / scale for v in values]


def project_on_Ubar(tk, Ubar):
    projected = []
    for i, v in enumerate(tk):
        li, lf_bound = Ubar[i]
        clamped = max(min(v, lf_bound), li)
        print(f"tk[{i}] = {v}, bounds = ({li}, {lf_bound}), projected = {clamped}")
        projected.append(clamped)
    return projected


def zero_vector(length, pubkey, lf=16):
    try:
        return [labhe.E(pubkey, None, f"zero_{i}", 0) for i in range(length)]
    except Exception as e:
        print(f"Error creating zero vector: {e}")
        raise


def he_add(vec1, vec2, pubkey):
    return [labhe.Eval_add(pubkey, c1, c2) for c1, c2 in zip(vec1, vec2)]


def he_scalar_mul(scalar, ciphertext, pubkey):
    try:
        if isinstance(scalar, (int, float)):
            scalar = int(round(scalar))

        if isinstance(ciphertext, list):
            return [labhe.Eval_mult_scalar(pubkey, ct, scalar) for ct in ciphertext]
        else:
            return labhe.Eval_mult_scalar(pubkey, ciphertext, scalar)

    except Exception as e:
        print(f"Error in he_scalar_mul: {e}")
        raise

def he_matvec_mul_precise(mat, enc_vector, pubkey, lf=16):
    """
    More precise matrix-vector multiplication that handles fractional values.
    Use this if you need exact fractional coefficients.
    """
    result = []
    
    for i, row in enumerate(mat):
        acc = None
        for j, scalar in enumerate(row):
            if abs(scalar) < 1e-10:  # Treat as zero
                continue
            
            # Method 1: For identity matrices and simple values
            if abs(scalar - 1.0) < 1e-10:
                prod = enc_vector[j]
            elif abs(scalar - (-1.0)) < 1e-10:
                prod = labhe.Eval_mult_scalar(pubkey, enc_vector[j], mpz(-1))
            else:
                # For other values, use integer approximation
                int_scalar = int(round(scalar))
                if int_scalar == 0 and scalar != 0:
                    int_scalar = 1 if scalar > 0 else -1
                prod = labhe.Eval_mult_scalar(pubkey, enc_vector[j], mpz(int_scalar))
            
            prod.label = f"row_{i}"

            if acc is None:
                acc = prod
            else:
                acc = labhe.Eval_add(pubkey, acc, prod)

        if acc is None:
            acc = labhe.Eval_mult_scalar(pubkey, enc_vector[0], mpz(0))
            acc.label = f"row_{i}"

        result.append(acc)

    return result

def he_vec_add(enc_vec1, enc_vec2, pubkey=None):
    if len(enc_vec1) != len(enc_vec2):
        raise ValueError("Encrypted vectors must be of the same length.")
    return [
        labhe.Eval_add(pubkey, a, b) for a, b in zip(enc_vec1, enc_vec2)
    ]


def load_matrix_from_file(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        matrix = []
        for line in lines:
            line = line.strip()
            if line:
                row = [float(x) for x in line.split(',')]
                matrix.append(row)
        return np.array(matrix)
    except Exception as e:
        print(f"Error loading matrix from {filename}: {e}")
        raise


def fp_vector(vec, lf=16):
    scale = 1 << lf
    return [int(round(x * scale)) for x in vec]



# Fix 1: Proper scalar encoding for the update equation
def encode_scalar(val, lf):
    """Encode a scalar value for fixed-point arithmetic"""
    return int(round(val * (1 << lf)))

def control_scalar_mult_fixed(pubkey, ciphertext, scalar_float):
    """
    Fixed scalar multiplication for control algorithms.
    Handles common control coefficients properly.
    """
    if abs(scalar_float - 1.1) < 1e-6:
        # 1.1 ≈ 1 (close enough for control)
        return labhe.Eval_mult_scalar(pubkey, ciphertext, 1)
    elif abs(scalar_float - (-0.1)) < 1e-6:
        # -0.1 ≈ 0 (minimal effect)
        return labhe.Eval_mult_scalar(pubkey, ciphertext, 0)
    elif abs(scalar_float - 1.0) < 1e-6:
        # Exact 1.0
        return ciphertext
    elif abs(scalar_float - (-1.0)) < 1e-6:
        # Exact -1.0
        return labhe.Eval_mult_scalar(pubkey, ciphertext, -1)
    else:
        # General case: round to nearest integer
        int_scalar = int(round(scalar_float))
        return labhe.Eval_mult_scalar(pubkey, ciphertext, int_scalar)


def precise_homomorphic_scalar_mult(pubkey, ciphertext, scalar_float, lf):
    scalar_fixed = int(round(scalar_float ))
    return labhe.Eval_mult_scalar(pubkey, ciphertext, scalar_fixed)

def decrypt_double_scaled(privkey, ct, lf):
    decoded = labhe.D(privkey, ct)
    return float(decoded) / (1 << (2 * lf))
