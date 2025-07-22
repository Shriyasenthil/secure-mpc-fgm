

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
    mpk, msk = paillier.generate_paillier_keypair(None, n_length)
    lpk = LabHEPublicKey(mpk)

    if isinstance(usk, list) and len(usk) == 1:
        upk = [mpk.encrypt(usk[0])]  # Encrypt the single element
    else:
        upk = util_fpv.encrypt_vector(mpk, usk)

    lsk = LabHEPrivateKey(msk, upk)
    return lpk, lsk


def Init():
    
    from paillier import generate_paillier_keypair
    pubkey, privkey = generate_paillier_keypair()
    return privkey, pubkey

class LabHEPublicKey(object):
    
    def __init__(self, mpk):
        self.Pai_key = mpk
        self.n = mpk.n
        self.max_int = mpk.n // 3 - 1
        self.nsquare = mpk.n ** 2 
    @property
    def n_sq(self):
        return self.Pai_key.nsquare 
    
    def offline_gen_secret(self, label, usk):
        
        self.usk = usk  
        hash = hashlib.sha3_224()
        hash.update((bin(usk) + str(label)).encode('utf-8'))

        secret = int(hash.hexdigest(),16)
        return secret

    def offline_encrypt(self, secret):
        pass

    def encrypt(self, value, r_value=None):
        return self.Pai_key.encrypt(value, r_value)

    def encrypt_with_label(self, plaintext, secret, enc_secret=None, r_value=None):
        import numpy
        from gmpy2 import mpz

        if not isinstance(secret, int) and not isinstance(secret, type(mpz(1))) and not isinstance(secret, numpy.integer):
            raise TypeError('Expected int type secret but got: %s' % type(secret))
        if not isinstance(plaintext, int) and not isinstance(plaintext, type(mpz(1))) and not isinstance(plaintext, numpy.integer):
            raise TypeError('Expected int type plaintext but got: %s' % type(plaintext))
        if enc_secret is not None and not isinstance(enc_secret, paillier.EncryptedNumber):
            raise TypeError('Expected encrypted secret to be type Paillier.EncryptedNumber or None but got: %s' % type(enc_secret))

        if enc_secret is None:
            ciphertext = plaintext - secret, self.Pai_key.encrypt(secret, r_value)
        else:
            ciphertext = plaintext - secret, enc_secret

        return LabEncryptedNumber(self, ciphertext)



class LabHEPrivateKey(object):
    def __init__(self, msk, upk):
        self.msk = msk
        self.upk = upk
        if isinstance(upk, list) and len(upk) == 1:
            self.usk = msk.decrypt(upk[0])
        elif isinstance(upk, list):
            self.usk = util_fpv.decrypt_vector(msk, upk)
        else:
            self.usk = msk.decrypt(upk)

        self.n = msk.n
        self.mpk = msk.public_key

    def __repr__(self):
        pub_repr = repr(self.mpk)
        return "<LabHEPrivateKey for {}>".format(pub_repr)

    def decrypt(self, encrypted_number, secret=None):
        if not isinstance(encrypted_number, LabEncryptedNumber) and not isinstance(encrypted_number, paillier.EncryptedNumber):
            raise TypeError('Expected encrypted_number to be a LabEncryptedNumber or Paillier EncryptedNumber, not: %s' % type(encrypted_number))


        if isinstance(encrypted_number, LabEncryptedNumber):
            if self.mpk != encrypted_number.mpk:
                raise ValueError('Encrypted number was encrypted against a different key!')

            ciphertext_data = encrypted_number.ciphertext

            if isinstance(ciphertext_data, (list, tuple)):
                if len(ciphertext_data) == 2:

                    if secret is None:
                        secret = self.raw_offline_decrypt(ciphertext_data[1])
                    elif isinstance(secret, paillier.EncryptedNumber):
                        secret = self.raw_offline_decrypt(secret)
                    elif not isinstance(secret, int):
                        raise TypeError("Invalid secret type for decryption.")

                    ciphertext = ciphertext_data[0]
                else:
                    raise ValueError('Invalid ciphertext format: LabEncryptedNumber should be of length 2 if tuple/list.')

            elif isinstance(ciphertext_data, int):

                if secret is None:
                    raise TypeError('Decryption requires a secret for single-component LabEncryptedNumber.')
                elif isinstance(secret, paillier.EncryptedNumber):
                    secret = self.raw_offline_decrypt(secret)
                elif not isinstance(secret, int):
                    raise TypeError("Invalid secret type for decryption.")

                ciphertext = ciphertext_data

            else:
                raise TypeError('LabEncryptedNumber.ciphertext must be int, list, or tuple — got %s' % type(ciphertext_data))

        else:
            if secret is None:
                raise TypeError('Expected a secret as an input for PaillierEncryptedNumber')
            elif isinstance(secret, paillier.EncryptedNumber):
                secret = self.raw_offline_decrypt(secret)
            elif not isinstance(secret, int):
                raise TypeError("Invalid secret type for Paillier decryption.")
            ciphertext = self.msk.decrypt(encrypted_number)

        return self.raw_decrypt(ciphertext, secret)



    def raw_decrypt(self, ciphertext, secret):
        if not isinstance(ciphertext, int) and not isinstance(ciphertext, type(mpz(1))) and not isinstance(ciphertext, numpy.int64):
            raise TypeError('Expected ciphertext to be an int, not: %s' % type(ciphertext))

        value = ciphertext + secret
        if value < self.n / 3:
            return int(value)
        else:
            return int(value - self.n)

    def raw_offline_decrypt(self, encr_secret):
        if isinstance(encr_secret, int):
            encr_secret = paillier.EncryptedNumber(self.msk.public_key, encr_secret, 0)

        if not isinstance(encr_secret, paillier.EncryptedNumber):
            raise TypeError(f"Expected EncryptedNumber for raw_offline_decrypt, got {type(encr_secret)}")

        secret = self.msk.decrypt(encr_secret)
        return secret

class LabEncryptedNumber(object):
    def __init__(self, mpk, ciphertext):
        self.mpk = mpk
        self.ciphertext = ciphertext
        if isinstance(self.ciphertext, LabEncryptedNumber) or isinstance(self.ciphertext, paillier.EncryptedNumber):
            raise TypeError('Ciphertext should be an integer')
        if not isinstance(self.mpk, LabHEPublicKey):
            raise TypeError('mpk should be a LabHEPublicKey')

    def __add__(self, other):
        #Add a LabEncryptedNumber, Paillier EncryptedNumber, or scalar.
        if isinstance(other, LabEncryptedNumber) or isinstance(other, paillier.EncryptedNumber):
            return self._add_encrypted(other)
        else:
            return self._add_scalar(other)

    def __radd__(self, other):
        return self.__add__(other)

    def __mul__(self, other):
        return self._mul_scalar(other)

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



    def _encrypt_zero(self):

        import random
        r = random.randint(1, self.mpk.n - 1)
        zero_c0 = pow(r, self.mpk.n, self.mpk.nsquare)

        zero_c1 = self.mpk.encrypt(0) 

        return LabEncryptedNumber(self.mpk, (zero_c0, zero_c1))

    def _negate(self):
 
        c0, c1_encrypted = self.ciphertext
        neg_c0 = pow(c0, self.mpk.n - 1, self.mpk.nsquare)
        neg_c1_encrypted = -c1_encrypted
        return LabEncryptedNumber(self.mpk, (neg_c0, neg_c1_encrypted))

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
            sum_ciphertext = a + b 
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