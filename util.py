
import os
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
from binascii import hexlify, unhexlify

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

try:
    from Crypto.Util import number
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

_USE_MOD_FROM_GMP_SIZE = (1 << (8*2))


def powmod(a, b, c):

    if a == 1:
        return 1
    if not HAVE_GMP or max(a, b, c) < _USE_MOD_FROM_GMP_SIZE:
        return pow(a, b, c)
    else:
        return int(gmpy2.powmod(a, b, c))


def invert(a, b):

    if HAVE_GMP:
        return int(gmpy2.invert(a, b))
    else:
       
        for d in range(1, b):
            r = (d * a) % b
            if r == 1:
                break
        else:
            raise ValueError('%d has no inverse mod %d' % (a, b))
        return d


def getprimeover(N):

    if HAVE_GMP:
        randfunc = random.SystemRandom()
        r = gmpy2.mpz(randfunc.getrandbits(N))
        r = gmpy2.bit_set(r, N - 1)
        return int(gmpy2.next_prime(r))
    elif HAVE_CRYPTO:
        return number.getPrime(N, os.urandom)
    else:
        raise NotImplementedError("No pure python implementation sorry")


def isqrt(N):
    # returns the integer square root of N
    if HAVE_GMP:
        return int(gmpy2.isqrt(N))
    else:
        return improved_i_sqrt(N)


def improved_i_sqrt(n):

    assert n >= 0
    if n == 0:
        return 0
    i = n.bit_length() >> 1    # i = floor( (1 + floor(log_2(n))) / 2 )
    m = 1 << i    # m = 2^i
  
    while (m << i) > n: # (m<<i) = m*(2^i) = m*m
        m >>= 1
        i -= 1
    d = n - (m << i) # d = n-m^2
    for k in range(i-1, -1, -1):
        j = 1 << k
        new_diff = d - (((m<<1) | j) << k) # n-(m+2^k)^2 = n-m^2-2*m*2^k-2^(2k)
        if new_diff >= 0:
            d = new_diff
            m |= j
    return m


def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = urlsafe_b64encode(payload)
    return encode.decode('utf-8').rstrip('=')


def base64url_decode(payload):
    l = len(payload) % 4
    if l == 2:
        payload += '=='
    elif l == 3:
        payload += '='
    elif l != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))


def base64_to_int(source):
    return int(hexlify(base64url_decode(source)), 16)


def int_to_base64(source):
    assert source != 0
    I = hex(source).rstrip("L").lstrip("0x")
    return base64url_encode(unhexlify((len(I) % 2) * '0' + I))