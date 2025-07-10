# LabHE implementation from https://eprint.iacr.org/2017/326
# Uses Paillier as underlying additively homomorphic encryption and Keccak as the PRF

import random
import hashlib
import math
import sys
import numpy
from gmpy2 import mpz
import paillier
import util_fpv

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

DEFAULT_KEYSIZE = 1024

def generate_LabHE_keypair(usk, n_length=DEFAULT_KEYSIZE):
   
    mpk, msk = paillier.generate_paillier_keypair(None,n_length)
    # lsk = msk, mpk.encrypt(usk)
    # lpk = mpk, usk

    lpk = LabHEPublicKey(mpk)
    if len(usk) == 1:
        lsk = LabHEPrivateKey(msk, mpk.encrypt(usk))
    else:
        lsk = LabHEPrivateKey(msk, util_fpv.encrypt_vector(mpk,usk))

    return lpk, lsk

def Init():
    """Initialize LabHE by generating Paillier keypair."""
    from paillier import generate_paillier_keypair
    pubkey, privkey = generate_paillier_keypair()
    return privkey, pubkey



class LabHEPublicKey(object):
    
    def __init__(self, mpk):
        self.Pai_key = mpk
        self.n = mpk.n
        self.max_int = mpk.n // 3 - 1

    @property
    def n_sq(self):
        return self.Pai_key.nsquare  # ✅ This will fix the AttributeError

    def offline_gen_secret(self, label, usk):
        
        self.usk = usk  
        hash = hashlib.sha3_224()
        hash.update(('%s%s' % (bin(usk).encode('utf-8'), bin(label).encode('utf-8'))).encode('utf-8'))
        secret = int(hash.hexdigest(),16)
        return secret

    def offline_encrypt(self, secret):
 

    def encrypt(self, plaintext, secret, enc_secret=None, r_value=None):
 
        if not isinstance(secret, int) and not isinstance(secret, type(mpz(1))) and not isinstance(secret, numpy.integer):
            raise TypeError('Expected int type secret but got: %s' %
                            type(secret))
        if not isinstance(plaintext, int) and not isinstance(plaintext, type(mpz(1))) and not isinstance(plaintext, numpy.integer):
            raise TypeError('Expected int type plaintext but got: %s' %
                            type(plaintext))
        if not isinstance(enc_secret, paillier.EncryptedNumber) and enc_secret is not None:
            raise TypeError('Expected encrypted secret to be type Paillier.EncryptedNumber or None but got: %s' %
                            type(enc_secret))
        if enc_secret is None:
            ciphertext = plaintext - secret, self.Pai_key.encrypt(secret,r_value)
        else:
            ciphertext = plaintext - secret, enc_secret
        encrypted_number = LabEncryptedNumber(self, ciphertext)
        return encrypted_number


class LabHEPrivateKey(object):
 
    def __init__(self, msk, upk):
        self.msk = msk
        self.upk = upk
        if len(upk) == 1:
            self.usk = msk.decrypt(upk)
        else:
            self.usk = util_fpv.decrypt_vector(msk,upk)
        self.n = msk.n
        self.mpk = msk.public_key

    def __repr__(self):
        pub_repr = repr(self.mpk)
        return "<LabHEPrivateKey for {}>".format(pub_repr)

    def decrypt(self, encrypted_number, secret=None):
     
        if not isinstance(encrypted_number, LabEncryptedNumber) and not isinstance(encrypted_number, paillier.EncryptedNumber): 
            raise TypeError('Expected encrypted_number to be an LabEncryptedNumber or paillier.EncryptedNumber'
                            ' not: %s' % type(encrypted_number))

        
        if isinstance(encrypted_number, LabEncryptedNumber):
            if self.mpk != encrypted_number.mpk:
                raise ValueError('encrypted_number was encrypted against a '
                                 'different key!')

            if secret is None:
                if len(encrypted_number.ciphertext) == 2:
                    secret = self.raw_offline_decrypt(encrypted_number.ciphertext[1])
                    ciphertext = encrypted_number.ciphertext[0]
                else:
                    if len(encrypted_number.ciphertext) == 1:
                        raise TypeError('Expected a secret as an input')
            else:
                if isinstance(secret, paillier.EncryptedNumber):
                    secret = self.raw_offline_decrypt(secret)

            
            ciphertext = encrypted_number.ciphertext[0]
        else:
            if secret is None:
                raise TypeError('Expected a secret as an input')
            else:
                if isinstance(secret, paillier.EncryptedNumber):
                    secret = self.raw_offline_decrypt(secret)
            ciphertext = self.msk.decrypt(encrypted_number)

        return self.raw_decrypt(ciphertext, secret)


    def raw_decrypt(self, ciphertext, secret):
     
        if not isinstance(ciphertext, int) and not isinstance(ciphertext, type(mpz(1))) and not isinstance(ciphertext, numpy.int64):
            raise TypeError('Expected ciphertext to be an int, not: %s' %
                type(ciphertext))


        value = ciphertext + secret
        if value < self.n/3:
            return int(value)
        else:
            return int(value - self.n)

    def raw_offline_decrypt(self, encr_secret):
   
        secret = self.msk.decrypt(encr_secret)
        return secret

class LabEncryptedNumber(object):
  

    ####### There are two types of ciphertexts, beware! LabEncryptedNumber and paillier.EncryptedNumber
    def __init__(self, mpk, ciphertext):
        self.mpk = mpk
        self.ciphertext = ciphertext
        if isinstance(self.ciphertext, LabEncryptedNumber) | isinstance(self.ciphertext, paillier.EncryptedNumber):
            raise TypeError('Ciphertext should be an integer')
        if not isinstance(self.mpk, LabHEPublicKey):
            raise TypeError('mpk should be a LabHEPublicKey')

    def __add__(self, other):
        """Add an int, `LabEncryptedNumber` or `EncodedNumber`."""
        if isinstance(other, LabEncryptedNumber) | isinstance(other, paillier.EncryptedNumber):
            return self._add_encrypted(other)
        else:
            return self._add_scalar(other)

    def __radd__(self, other):
      
        return self.__add__(other)
    

import gmpy2
from gmpy2 import mpz

class LabEncryptedNumber:

    def __init__(self, mpk, ciphertext):
        self.mpk = mpk  # LabHEPublicKey
        self.ciphertext = ciphertext  # Tuple (c0, c1)
    ...
    def __mul__(self, other):
        """Multiply by a scalar (int or mpz) or another LabEncryptedNumber."""
        if isinstance(other, LabEncryptedNumber):
            return self._mul_encrypted(other)

        elif isinstance(other, (int, mpz, gmpy2.mpz)):
            if isinstance(other, mpz) or isinstance(other, gmpy2.mpz):
                other = int(other)  # convert mpz to native int

            if other < 0:
                other = other + self.mpk.n
            return self._mul_scalar(other)

        else:
            raise TypeError(f"Unsupported type for multiplication: {type(other)}")

    def __add__(self, other):
       if isinstance(other, LabEncryptedNumber):
           c0 = (self.ciphertext[0] + other.ciphertext[0]) % self.mpk.n_sq
           c1 = self.ciphertext[1] + other.ciphertext[1]  # Do NOT mod encrypted part
           return LabEncryptedNumber(self.mpk, (c0, c1))

       else:
           raise TypeError("Addition only supported between LabEncryptedNumbers.")


        
    def __radd__(self, other):
       return self.__add__(other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __sub__(self, other):
        return self + (other * -1)

    def __rsub__(self, other):
        return other + (self * -1)

    def __truediv__(self, scalar):
        return self.__mul__(1 / scalar)


    def _add_scalar(self, scalar):
 

        a, b = self.ciphertext, scalar

        if len(a)==2:
            sum_ciphertext = a[0]+b, a[1]
        else:
            sum_ciphertext = a + b # The override of sum is taken care in Paillier
        return LabEncryptedNumber(self.mpk, sum_ciphertext)

    def _add_encrypted(self, other):
  
        if isinstance(self, LabEncryptedNumber) & isinstance(other, LabEncryptedNumber):
            if self.mpk != other.mpk :
                raise ValueError("Attempted to add numbers encrypted against "
                                "different public keys!")
            a, b = self.ciphertext, other.ciphertext
            sum_ciphertext = a[0] + b[0], a[1] + b[1]
        else:
            if isinstance(self, LabEncryptedNumber) & isinstance(other, paillier.EncryptedNumber):
                if self.mpk.Pai_key != other.public_key :
                    raise ValueError("Attempted to add numbers encrypted against "
                                    "different public keys!")
                a, b = self.ciphertext, other
                len_a = len(a)
                if len_a == 2:
                    sum_ciphertext = a[0], a[1] + b
                else:
                    sum_ciphertext = a + b
            else:
                    if isinstance(other, LabEncryptedNumber) & isinstance(self, paillier.EncryptedNumber):
                        if other.mpk.Pai_key != self.public_key :
                            raise ValueError("Attempted to add numbers encrypted against "
                                            "different public keys!")
                        a, b = other.ciphertext, self
                        len_b = len(b)
                        if len_b == 2:
                            sum_ciphertext = b[0], a + b[1]
                        else:
                            sum_ciphertext = a + b

        return LabEncryptedNumber(self.mpk, sum_ciphertext)


    def _mul_scalar(self, plaintext):
   
        if not isinstance(plaintext, int) and not isinstance(plaintext, type(mpz(1))) and not isinstance(plaintext, numpy.int64):
            raise TypeError('Expected ciphertext to be int, not %s' %
                type(plaintext))

        if plaintext < 0 or plaintext >= self.mpk.n:
            raise ValueError('Scalar out of bounds: %i' % plaintext)

        a, b = self.ciphertext, plaintext

        if len(a) == 2:
            prod_ciphertext = a[0]*b, a[1]*b
        else:
            prod_ciphertext = a*b
        return LabEncryptedNumber(self.mpk, prod_ciphertext)

    def _mul_encrypted(self, other):
       

        a, b = self.ciphertext, other.ciphertext

        if len(a) < 2:
            raise TypeError('Expected first factor to be a full LabHE encryption, not %s' %
                type(a))

        if len(b) < 2:
            raise TypeError('Expected second factor to be a full LabHE encryption, not %s' %
                type(b))

        prod_ciphertext = a[0]*b[0] + a[0]*b[1] + a[1]*b[0]

        return prod_ciphertext

    def mlt3(self, other1, other2, extra):
        
        if isinstance(other1, LabEncryptedNumber) and isinstance(other2, LabEncryptedNumber):
            if (isinstance(extra[0], paillier.EncryptedNumber) and isinstance(extra[1], paillier.EncryptedNumber) 
              and isinstance(extra[2], paillier.EncryptedNumber)):

                a, b, c = self.ciphertext, other1.ciphertext, other2.ciphertext
                s1s2, s1s3, s2s3 = extra[0], extra[1], extra[2]

                if len(a) < 2:
                    raise TypeError('Expected first factor to be a full LabHE encryption, not %s' %
                        type(a))

                if len(b) < 2:
                    raise TypeError('Expected second factor to be a full LabHE encryption, not %s' %
                        type(b))

                if len(c) < 2:
                    raise TypeError('Expected third factor to be a full LabHE encryption, not %s' %
                        type(b))

                prod_ciphertext = (a[0]*b[0]*c[0] + a[0]*s2s3 + b[0]*s1s3 + c[0]*s1s2 + 
                                    (a[0]*b[0])*c[1] + (a[0]*c[0])*b[1] + (b[0]*c[0])*a[1])

            else:
                raise TypeError('Need to have the extra information for multiplication.')
        else:
            raise TypeError('Need to have full LabHE encryptions')

        return prod_ciphertext

# To merge with mlt3
    def mlt4(self, other1, other2, other3, extra):
      
        if (isinstance(other1, LabEncryptedNumber) and isinstance(other2, LabEncryptedNumber) and
             isinstance(other2, LabEncryptedNumber)):
            len_extra = len(extra)
            if len_extra == 10:
                flag = 1
                for k in range(len_extra):
                    flag = flag and isinstance(extra[k], paillier.EncryptedNumber)
                if (flag == 1):

                    a, b, c, d = self.ciphertext, other1.ciphertext, other2.ciphertext, other3.ciphertext
                    s1s2, s1s3, s1s4, s2s3, s2s4, s3s4  = extra[0], extra[1], extra[2], extra[3], extra[4], extra[5]
                    s1s2s3, s1s2s4, s1s3s4, s2s3s4 = extra[6], extra[7], extra[8], extra[9]

                    prod_ciphertext = (a[0]*b[0]*c[0]*d[0] + a[0]*s2s3s4 + b[0]*s1s3s4 + c[0]*s1s2s4 + 
                                        d[0]*s1s2s3 + (a[0]*b[0])*s3s4 + (a[0]*c[0])*s2s4 + (a[0]*d[0]*s2s3) +
                                        (b[0]*c[0])*s1s4 + (b[0]*d[0])*s1s3 + (c[0]*d[0])*s1s2 + 
                                        (a[0]*b[0]*c[0])*d[1] + (a[0]*b[0]*d[0])*c[1] + (a[0]*c[0]*d[0])*b[1] + 
                                        (b[0]*c[0]*d[0])*a[1])
                else:
                    raise TypeError('The extra information has to be Paillier encryptions.')

            else:
                raise TypeError('Need to have the extra information for multiplication.')
        else:
            raise TypeError('Need to have full LabHE encryptions')

        return prod_ciphertext
    
def generate_secret(pubkey):
    
    return random.randint(1, pubkey.n // 3)

