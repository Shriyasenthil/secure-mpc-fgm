import random
import hashlib
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


def D(priv, ct):
    L = mpz(hash_label(ct.label))
    u = powmod(ct.ciphertext, priv.lambda_param, priv.nsquare)
    l = priv.L_function(u)
    mL = (l * priv.mu) % priv.n
    m = (mL - L) % priv.n
    
    # Convert to signed representation
    # If m > n/2, it represents a negative number
    if m > priv.n // 2:
        m = m - priv.n
    
    return m

def Eval_add(pub, ct1, ct2):
    assert ct1.label == ct2.label, "Labels must match for Eval_add"
    c = (ct1.ciphertext * ct2.ciphertext) % pub.nsquare
    return Ciphertext(ct1.label, c)

def Eval_mult_scalar(pub, ct, scalar):
    if not isinstance(scalar, mpz):
        scalar = mpz(scalar)
    c = powmod(ct.ciphertext, scalar, pub.nsquare)
    return Ciphertext(ct.label, c)

def Eval(op, *args):
    if op == 'add':
        return Eval_add(*args)
    elif op == 'mul':
        return Eval_mult_scalar(*args)
    else:
        raise ValueError(f"Unsupported Eval operation: {op}")

def Encode(val, pubkey, lf):
    scale = 1 << lf
    encoded = int(round(val * scale))
    
    # Check if the encoded value is within valid range
    max_val = pubkey.n // 2
    if abs(encoded) > max_val:
        raise ValueError(f"Value {val} too large for encoding with lf={lf}")
    
    # Convert negative values to positive representation
    if encoded < 0:
        encoded = encoded + pubkey.n
    
    return encoded

def encrypt(val, label="enc", lf=16, already_encoded=False):
    encoded = val if already_encoded else Encode(val, pubkey, lf)
    return E(pubkey, None, label, encoded)

def decrypt(priv, ct, lf=16):
    decoded = D(priv, ct)
    # Handle both positive and negative decoded values
    return float(decoded) / (1 << lf)
