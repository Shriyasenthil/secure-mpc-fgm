#!/usr/bin/env python3
# Adapted from pyphe. Transform it to be a fixed-point library, no encoding

import random
import hashlib
import math
import sys

import numpy
try:
    from collections.abc import Mapping
except ImportError:
    Mapping = dict


from util import invert, powmod, getprimeover, isqrt
from gmpy2 import mpz

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

DEFAULT_KEYSIZE = 512


def generate_paillier_keypair(private_keyring=None, n_length=DEFAULT_KEYSIZE):
 
    p = q = n = None
    n_len = 0
    while n_len != n_length:
        p = getprimeover(n_length // 2)
        q = p
        while q == p:
            q = getprimeover(n_length // 2)
        n = p * q
        n_len = n.bit_length()

    public_key = PaillierPublicKey(n)
    private_key = PaillierPrivateKey(public_key, p, q)

    if private_keyring is not None:
        private_keyring.add(private_key)

    return public_key, private_key

class PaillierPublicKey(object):
  
    def __init__(self, n):
        self.g = n + 1
        self.n = n
        self.nsquare = n * n
        self.max_int = n // 3 - 1

    def __repr__(self):
        nsquare = self.nsquare.to_bytes(1024, 'big')
        g = self.g.to_bytes(1024, 'big')
        publicKeyHash = hashlib.sha1(nsquare + g).hexdigest()
        return "<PaillierPublicKey {}>".format(publicKeyHash[:10])

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return hash(self.n)

    def raw_encrypt(self, plaintext, r_value=None):
    
        if not isinstance(plaintext, int) and not isinstance(plaintext, type(mpz(1))) and not isinstance(plaintext, numpy.int64):
            raise TypeError('Expected int type plaintext but got: %s' %
                            type(plaintext))

        if self.n - self.max_int <= plaintext < self.n:
           
            neg_plaintext = self.n - plaintext  
            neg_ciphertext = (self.n * neg_plaintext + 1) % self.nsquare
            nude_ciphertext = invert(neg_ciphertext, self.nsquare)
        else:
           
            nude_ciphertext = (self.n * plaintext + 1) % self.nsquare

        # r = r_value or self.get_random_lt_n()
        # obfuscator = powmod(r, self.n, self.nsquare)
        r = r_value or powmod(self.get_random_lt_n(), self.n, self.nsquare) # Pass the precomputed obfuscator
        obfuscator = r

        return (nude_ciphertext * obfuscator) % self.nsquare

    def get_random_lt_n(self):
        """Return a cryptographically random number less than :attr:`n`"""
        return random.SystemRandom().randrange(1, self.n)

    def encrypt(self, value, r_value=None): ### Do raw_encrypt
      

        obfuscator = r_value or 1
        if value < 0:
            value = value + self.n
        ciphertext = self.raw_encrypt(value, r_value=obfuscator)
        encrypted_number = EncryptedNumber(self, ciphertext)
        if r_value is None:
            encrypted_number.obfuscate()
        return encrypted_number

        return self.encrypt_encoded(encoding, r_value)

class PaillierPrivateKey(object):

    def __init__(self, public_key, p, q):
        if not p * q == public_key.n:
            raise ValueError('given public key does not match the given p and q.')
        if p == q:  # check that p and q are different, otherwise we can't compute p^-1 mod q
            raise ValueError('p and q have to be different')
        self.public_key = public_key
        if q < p:  # ensure that p < q
            self.p = q
            self.q = p
        else:
            self.p = p
            self.q = q
        self.psquare = self.p * self.p
        self.qsquare = self.q * self.q
        self.p_inverse = invert(self.p, self.q)
        self.hp = self.h_function(self.p, self.psquare)
        self.hq = self.h_function(self.q, self.qsquare)
        self.n = public_key.n

    @staticmethod
    def from_totient(public_key, totient):
        p_plus_q = public_key.n - totient + 1
        p_minus_q = isqrt(p_plus_q * p_plus_q - public_key.n * 4)
        q = (p_plus_q - p_minus_q) // 2
        p = p_plus_q - q
        if not p * q == public_key.n:
            raise ValueError('given public key and totient do not match.')
        return PaillierPrivateKey(public_key, p, q)

    def __repr__(self):
        pub_repr = repr(self.public_key)
        return "<PaillierPrivateKey for {}>".format(pub_repr)
    
    def decrypt(self, encrypted_number):
        import traceback
        import pdb
        print(f"\n[DEBUG decrypt] Got type: {type(encrypted_number)}")

        # Patch to unwrap LabEncryptedNumber without circular import
        try:
            import labhe
        except ImportError:
            labhe = None

        if labhe is not None and isinstance(encrypted_number, labhe.LabEncryptedNumber):
            ct = encrypted_number.ciphertext
            if isinstance(ct, (tuple, list)) and len(ct) == 2 and isinstance(ct[0], EncryptedNumber):
                encrypted_number = ct[0]
            elif isinstance(ct, EncryptedNumber):
                encrypted_number = ct
            else:
                raise TypeError(
                    f'Could not unwrap LabEncryptedNumber into EncryptedNumber, got ciphertext type {type(ct)}'
                )

        if not isinstance(encrypted_number, EncryptedNumber):
            raise TypeError(
                'Expected encrypted_number to be an EncryptedNumber'
                ' not: %s' % type(encrypted_number)
            )

        if self.public_key != encrypted_number.public_key:
            raise ValueError('encrypted_number was encrypted against a different key!')

        return self.raw_decrypt(encrypted_number.ciphertext(be_secure=False))

    def raw_decrypt(self, ciphertext):
        if not isinstance(ciphertext, int) and not isinstance(ciphertext, type(mpz(1))) and not isinstance(ciphertext, numpy.int64):
            raise TypeError('Expected ciphertext to be an int, not: %s' % type(ciphertext))

        decrypt_to_p = self.l_function(powmod(ciphertext, self.p - 1, self.psquare), self.p) * self.hp % self.p
        decrypt_to_q = self.l_function(powmod(ciphertext, self.q - 1, self.qsquare), self.q) * self.hq % self.q
        value = self.crt(decrypt_to_p, decrypt_to_q)

        if value < self.n / 3:
            return value
        else:
            return value - self.n

    def h_function(self, x, xsquare):
       
        return invert(self.l_function(powmod(self.public_key.g, x - 1, xsquare),x), x)
            
    
    def l_function(self, x, p):
        """ L(x,p) = (x-1)/p"""
        return (x - 1) // p
    
    def crt(self, mp, mq):
      
        u = (mq - mp) * self.p_inverse % self.q
        return mp + (u * self.p)

    def __eq__(self, other):
        return (self.p == other.p and self.q == other.q)

    def __hash__(self):
        return hash((self.p, self.q))

class PaillierPrivateKeyring(Mapping):
    
    def __init__(self, private_keys=None):
        if private_keys is None:
            private_keys = []
        public_keys = [k.public_key for k in private_keys]
        self.__keyring = dict(zip(public_keys, private_keys))

    def __getitem__(self, key):
        return self.__keyring[key]

    def __len__(self):
        return len(self.__keyring)

    def __iter__(self):
        return iter(self.__keyring)

    def __delitem__(self, public_key):
        del self.__keyring[public_key]

    def add(self, private_key):
        
        if not isinstance(private_key, PaillierPrivateKey):
            raise TypeError("private_key should be of type PaillierPrivateKey, "
                            "not %s" % type(private_key))
        self.__keyring[private_key.public_key] = private_key

    def decrypt(self, encrypted_number):
    
        relevant_private_key = self.__keyring[encrypted_number.public_key]
        return relevant_private_key.decrypt(encrypted_number)


class EncryptedNumber(object):
    
    def __init__(self, public_key, ciphertext):
        self.public_key = public_key
        self.__ciphertext = ciphertext
        self.__is_obfuscated = False
        if isinstance(self.ciphertext, EncryptedNumber):
            raise TypeError('ciphertext should be an integer')
        if not isinstance(self.public_key, PaillierPublicKey):
            raise TypeError('public_key should be a PaillierPublicKey')
        
    @property

    def ciphertext(self):
        if not self.__is_obfuscated:
            self.obfuscate()
        return self.__ciphertext

        
    

    def __add__(self, other):
        import labhe
        from labhe import LabEncryptedNumber
        if isinstance(other, EncryptedNumber) or isinstance(other, LabEncryptedNumber):
            return self._add_encrypted(other)
        else:
            return self._add_scalar(other)

    

    def __radd__(self, other):
        
        return self.__add__(other)

    def __mul__(self, other):
        """Multiply by an int."""
        if isinstance(other, EncryptedNumber):
            raise NotImplementedError('Good luck with that...')
        if other < 0:
            other = other + self.public_key.n
        product = self._raw_mul(other)

        return EncryptedNumber(self.public_key, product)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __sub__(self, other):
        return self + (other * -1)

    def __rsub__(self, other):
        return other + (self * -1)

    def __truediv__(self, scalar):
        return self.__mul__(1 / scalar)

    def ciphertext(self, be_secure=True):
        
        if be_secure and not self.__is_obfuscated:
            self.obfuscate()

        return self.__ciphertext

    def obfuscate(self):
       
        r = self.public_key.get_random_lt_n()
        r_pow_n = powmod(r, self.public_key.n, self.public_key.nsquare)
        self.__ciphertext = self.__ciphertext * r_pow_n % self.public_key.nsquare
        self.__is_obfuscated = True

    def _add_scalar(self, scalar):
    
        a, b = self, scalar

        # Don't bother to salt/obfuscate in a basic operation, do it
        # just before leaving the computer.
        encrypted_scalar = a.public_key.raw_encrypt(b, 1)

        sum_ciphertext = a._raw_add(a.ciphertext(False), encrypted_scalar)
        return EncryptedNumber(a.public_key, sum_ciphertext)

    def _add_encrypted(self, other):
        import labhe
        from labhe import LabEncryptedNumber
        if hasattr(self, 'public_key') and hasattr(other, 'public_key'):
            if self.public_key != other.public_key:
                raise ValueError("Mismatched public keys for addition")
            a, b = self, other
            sum_ciphertext = a._raw_add(a.ciphertext(False), b.ciphertext(False))
            return EncryptedNumber(a.public_key, sum_ciphertext)
        
        # Handle LabEncryptedNumber
        elif hasattr(self, 'mpk') and hasattr(other, 'mpk'):
            if self.mpk != other.mpk:
                raise ValueError("Mismatched public keys for addition")
            n_sq = self.mpk.n * self.mpk.n
            # ciphertexts are integers in LabEncryptedNumber
            sum_ciphertext = (self.ciphertext * other.ciphertext) % n_sq
            return LabEncryptedNumber(self.mpk, sum_ciphertext)
        elif (hasattr(self, 'public_key') and hasattr(other, 'mpk')) or (hasattr(self, 'mpk') and hasattr(other, 'public_key')):
            raise TypeError(f"Cannot add encrypted numbers of different types: {type(self)} + {type(other)}")
        
        else:
            raise TypeError(f"Unsupported encrypted number types for addition: {type(self)} + {type(other)}")

      

    def _raw_add(self, e_a, e_b):
        
        return e_a * e_b % self.public_key.nsquare

    def _raw_mul(self, plaintext):
       
        if not isinstance(plaintext, int) and not isinstance(plaintext, type(mpz(1))) and not isinstance(plaintext, numpy.int64):
            raise TypeError('Expected ciphertext to be int, not %s' %
                type(plaintext))

        if plaintext < 0 or plaintext >= self.public_key.n:
            raise ValueError('Scalar out of bounds: %i' % plaintext)

        if self.public_key.n - self.public_key.max_int <= plaintext:
            # Very large plaintext, play a sneaky trick using inverses
            neg_c = invert(self.ciphertext(False), self.public_key.nsquare)
            neg_scalar = self.public_key.n - plaintext
            return powmod(neg_c, neg_scalar, self.public_key.nsquare)
        else:
            return powmod(self.ciphertext(False), plaintext, self.public_key.nsquare)