import random
import hashlib
import math
from gmpy2 import mpz, powmod, invert, mpz_urandomb, random_state, next_prime, lcm

privkey = None
pubkey = None

class PublicKey:
    def __init__(self, n):
        self.n = n
        self.nsquare = n * n
        self.g = n + 1

class PrivateKey:
    def __init__(self, pub, p, q):
        self.pub = pub
        self.p = p
        self.q = q
        self.n = pub.n
        self.nsquare = self.n * self.n
        self.lambda_param = lcm(p - 1, q - 1)
        self.mu = invert(self.L_function(powmod(pub.g, self.lambda_param, self.nsquare)), self.n)

    def L_function(self, x):
        return (x - 1) // self.n

def Init(keysize):
    global privkey, pubkey
    rng = random_state(42)
    while True:
        p = next_prime(mpz_urandomb(rng, keysize // 2))
        q = next_prime(mpz_urandomb(rng, keysize // 2))
        if p != q:
            break
    n = p * q
    pub = PublicKey(n)
    priv = PrivateKey(pub, p, q)
    privkey, pubkey = priv, pub
    return priv, pub

def KeyGen(pub):
    return pub, pub

class Ciphertext:
    def __init__(self, label, ciphertext):
        self.label = label
        self.ciphertext = ciphertext

    def to_json(self):
        return {'label': self.label, 'ciphertext': str(self.ciphertext)}

    @staticmethod
    def from_json(obj):
        return Ciphertext(obj['label'], mpz(obj['ciphertext']))

Cipher = Ciphertext

def hash_label(label):
    return int(hashlib.sha256(label.encode()).hexdigest(), 16)

def E(pubkey, upk_unused, label, m):
    r = mpz(random.randint(1, pubkey.n - 1))
    L = mpz(hash_label(label))
    m = mpz(m)
    gm = powmod(pubkey.g, m, pubkey.nsquare)
    gL = powmod(pubkey.g, L, pubkey.nsquare)
    rn = powmod(r, pubkey.n, pubkey.nsquare)
    c = (gm * gL * rn) % pubkey.nsquare
    return Ciphertext(label, c)

def D(priv, ct, scalar_used=1):
    """Fixed decryption that handles scalar multiplication correctly"""
    L = mpz(hash_label(ct.label))
    u = powmod(ct.ciphertext, priv.lambda_param, priv.nsquare)
    l = priv.L_function(u)
    mL = (l * priv.mu) % priv.n

    adjusted_L = (L * scalar_used) % priv.n
    m = (mL - adjusted_L) % priv.n

    if m > priv.n // 2:
        m = m - priv.n

    return m

def Eval_add(pub, ct1, ct2):
    assert ct1.label == ct2.label, "Labels must match for Eval_add"
    c = (ct1.ciphertext * ct2.ciphertext) % pub.nsquare
    return Ciphertext(ct1.label, c)

def Eval_mult_scalar(pub, ct, scalar, debug=False):
    if not isinstance(scalar, mpz):
        scalar = mpz(scalar)
    if debug:
        print(f"[Eval_mult_scalar] Scalar = {scalar}, Bit length = {scalar.bit_length()}")
    if scalar.bit_length() > 30:
        raise ValueError(f"⚠ Scalar too large: {scalar}")

    c = powmod(ct.ciphertext, scalar, pub.nsquare)
    return Ciphertext(ct.label, c)

def Eval(op, *args):
    if op == 'add':
        return Eval_add(*args)
    elif op == 'mul':
        return Eval_mult_scalar(*args)
    else:
        raise ValueError(f"Unsupported Eval operation: {op}")

def get_max_value_for_lf(pubkey, lf):
    """Get maximum value that can be encoded for given label factor"""
    max_encoded = pubkey.max_int  # This is likely a very large mpz
    scale = lf  # Your label factor
    
    # Instead of converting to float directly, work with integers
    # and only convert at the end if the result is reasonable
    if max_encoded // scale > 10**15:  # Check if result would be too large for float
        # Return a reasonable maximum instead
        return 10**15  # or some other appropriate maximum
    else:
        return float(max_encoded // scale)  # Use integer division first

def find_optimal_lf(pubkey, value):
    max_encoded = pubkey.n // 2
    min_scale = abs(value) / max_encoded
    if min_scale <= 1:
        return 16
    min_lf = max(0, int(math.ceil(math.log2(min_scale))))
    return min_lf

def Encode(val, pubkey, lf):
    scale = 1 << lf
    encoded = int(round(val * scale))

    max_val = pubkey.n // 2
    if abs(encoded) > max_val:
        suggested_lf = find_optimal_lf(pubkey, val)
        max_possible = get_max_value_for_lf(pubkey, lf)
        raise ValueError(
            f"Value {val} too large for encoding with lf={lf}. "
            f"Maximum value with lf={lf} is ±{max_possible:.6f}. "
            f"Try using lf={suggested_lf} or smaller values."
        )

    if encoded < 0:
        encoded = encoded + pubkey.n

    return encoded

def encrypt(val, label="enc", lf=16, already_encoded=False, auto_scale=False):
    global pubkey

    if already_encoded:
        encoded = mpz(val)
    else:
        if auto_scale:
            max_possible = get_max_value_for_lf(pubkey, lf)
            if abs(val) > max_possible:
                lf = find_optimal_lf(pubkey, val)
                print(f"Auto-scaling: Using lf={lf} for value {val}")
        try:
            encoded = Encode(val, pubkey, lf)
        except ValueError as e:
            if auto_scale:
                lf = find_optimal_lf(pubkey, val)
                print(f"Retrying with lf={lf}")
                encoded = Encode(val, pubkey, lf)
            else:
                raise e

    if abs(encoded) > pubkey.n // 2:
        raise ValueError(f"Encoded value too large for encryption: {encoded}")

    return E(pubkey, None, label, encoded)

def decrypt(priv, ct, lf=16):
    decoded = D(priv, ct)

    if decoded.bit_length() > 1024:
        print(f"⚠ Warning: Decoded value too large (bit_length = {decoded.bit_length()})")
        raise ValueError("Decryption result too large to safely convert to float.")

    return float(decoded) / (1 << lf)

def get_key_info():
    if pubkey is None:
        return "No key initialized"
    return {
        'n_bit_length': pubkey.n.bit_length(),
        'max_plaintext': pubkey.n // 2,
        'max_value_lf16': get_max_value_for_lf(pubkey, 16),
        'max_value_lf8': get_max_value_for_lf(pubkey, 8),
        'max_value_lf4': get_max_value_for_lf(pubkey, 4),
    }

def check_value_compatibility(val, lf=16):
    if pubkey is None:
        return "No key initialized"
    max_possible = get_max_value_for_lf(pubkey, lf)
    compatible = abs(val) <= max_possible
    return {
        'value': val,
        'lf': lf,
        'max_possible': max_possible,
        'compatible': compatible,
        'suggested_lf': find_optimal_lf(pubkey, val) if not compatible else lf
    }
