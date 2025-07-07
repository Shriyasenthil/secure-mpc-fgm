import random

from gmpy2 import mpz, powmod, invert


DEFAULT_KEYSIZE = 512
DEFAULT_SECURITYSIZE = 160

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False


class DGKpubkey:
    def __init__(self, n, g, h, u, t=DEFAULT_SECURITYSIZE):
        self.n = n
        self.g = g
        self.h = h
        self.u = u
        self.t = t

    def raw_encrypt(self, plaintext, r_value=None):
        
        if not isinstance(plaintext, int) and not isinstance(plaintext, type(mpz(1))):
            raise TypeError(f'Expected int type plaintext but got: {type(plaintext)}')

        nude_ciphertext = powmod(self.g, plaintext, self.n)
        r = r_value or powmod(self.h, self.get_random_lt_2t(), self.n)
        obfuscator = r
        return (nude_ciphertext * obfuscator) % self.n

    def get_random_lt_2t(self):
        t2 = 2 * DEFAULT_SECURITYSIZE
        return random.SystemRandom().randrange(1, 2**t2)


class DGKprivkey:
    def __init__(self, p, q, v, pubkey):
        self.p = p
        self.q = q
        self.v = v
        self.pubkey = pubkey

    def raw_decrypt0(self, ciphertext):
        
        c = powmod(ciphertext, self.v, self.p)
        return 0 if c == 1 else 1


def loadkey(file):
    with open(file, 'r') as fin:
        data = [line.strip() for line in fin]
    p = mpz(data[0])
    q = mpz(data[1])
    u = mpz(data[2])
    vp = mpz(data[3])
    vq = mpz(data[4])
    fp = mpz(data[5])
    fq = mpz(data[6])
    g = mpz(data[7])
    h = mpz(data[8])
    return p, q, u, vp, vq, fp, fq, g, h


def add_encrypted(a, b, pubkey):
    return gmpy2.t_mod(gmpy2.mul(a, b), pubkey.n)

def diff_encrypted(a, b, pubkey):
    return add_encrypted(a, gmpy2.invert(b, pubkey.n), pubkey)

def mul_sc_encrypted(a, b, pubkey):
    return gmpy2.powmod(a, b, pubkey.n)