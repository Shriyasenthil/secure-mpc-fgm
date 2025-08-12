# Functions that involve quantization (fixed-point arithmetic) and vector operations
import os
import socket
import sys,struct
import json
from gmpy2 import mpz
import paillier
import numpy as np

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False



DEFAULT_KEYSIZE = 512
DEFAULT_MSGSIZE = 64 
DEFAULT_PRECISION = 24
DEFAULT_SECURITYSIZE = 100
DEFAULT_DGK = 160
NETWORK_DELAY = 0 


def encrypt(pubkey, x, coins=None):
	if (coins==None):
		return pubkey.encrypt(x)
	else: 
		return pubkey.encrypt(x,coins.pop())	

def encrypt_vector(pubkey, x, coins=None):
	size = np.shape(x)
	if len(size) == 1:
		if (coins==None):
			return [pubkey.encrypt(y) for y in x]
		else: 
			return [pubkey.encrypt(y,coins.pop()) for y in x]
	else:
		if (coins==None):
			return pubkey.encrypt(x)
		else: 
			return pubkey.encrypt(x,coins.pop())

def encrypt_matrix(pubkey, x, coins=None):
	size = np.shape(x)
	if len(size) == 2:
		if (coins==None):
			return [[pubkey.encrypt(int(y)) for y in z] for z in x]
		else: return [[pubkey.encrypt(int(y),coins.pop()) for y in z] for z in x]
	else:
		if len(size) == 1:
			if (coins==None):
				return [pubkey.encrypt(y) for y in x]
			else: 
				return [pubkey.encrypt(y,coins.pop()) for y in x]
		else:
			if (coins==None):
				return pubkey.encrypt(x)
			else: 
				return pubkey.encrypt(x,coins.pop())

def encrypt_multi_dim(pubkey, x, dim, coins = None):
	size = len(dim)
	if size > 3:
		if (coins==None):
			return [encrypt_multi_dim(pubkey,y,dim[0:size-1]) for y in x]
		else: return [encrypt_multi_dim(pubkey,y,dim[0:size-1],coins) for y in x]
	else:
		if (coins==None):
			return [encrypt_matrix(pubkey,y) for y in x]
		else: return [encrypt_matrix(pubkey,y,coins) for y in x]

def encrypt_multi_dim_np(pubkey, x, coins = None):
	size = len(x.shape)
	if size > 3:
		if (coins==None):
			return [encrypt_multi_dim_np(pubkey,y) for y in x]
		else: return [encrypt_multi_dim_np(pubkey,y,coins) for y in x]
	else:
		if (coins==None):
			return [encrypt_matrix(pubkey,y) for y in x]
		else: return [encrypt_matrix(pubkey,y,coins) for y in x]


def decrypt_vector(privkey, x):
    return [privkey.decrypt(i) for i in x]

def sum_encrypted_vectors(x, y):
	return [x[i] + y[i] for i in range(np.size(x))]

def diff_encrypted_vectors(x, y):
	return [x[i] - y[i] for i in range(len(x))] 

def mul_sc_encrypted_vectors(x, y):
    y_fixed = [fp(val, DEFAULT_PRECISION) if isinstance(val, float) or isinstance(val, int) else val for val in y]
    return [x[i] * y_fixed[i] for i in range(len(x))]

from functools import reduce
import operator

def mul_sc_encrypted_vectors(x, y):
    return [x[i] * y[i] for i in range(len(x))]  # x[i] must be LabEncryptedNumber

def dot_sc_encrypted_vectors(x, y):
    result = x[0] * y[0]
    for i in range(1, len(x)):
        result = result + (x[i] * y[i])
    return result


def Q_s(scalar,prec=DEFAULT_PRECISION):
	return int(scalar*(2**prec))/(2**prec)

def Q_vector(vec,prec=DEFAULT_PRECISION):
	if np.size(vec)>1:
		return [Q_s(x,prec) for x in vec]
	else:
		return Q_s(vec,prec)

def Q_matrix(mat,prec=DEFAULT_PRECISION):
	return [Q_vector(x,prec) for x in mat]

def fp(scalar, prec=DEFAULT_PRECISION):
    if isinstance(scalar, np.int64):
        scalar = int(scalar)

    if isinstance(scalar, float):
        return mpz(int(round(scalar * (2 ** prec))))

    elif prec < 0:
        return mpz(gmpy2.t_div_2exp(int(scalar), -prec))

    else:
        return mpz(gmpy2.mul(int(scalar), 2 ** prec))


def fp_vector(vec,prec=DEFAULT_PRECISION):
	if np.size(vec)>1:
		return [fp(x,prec) for x in vec]
	else:
		return fp(vec,prec)

def fp_matrix(mat,prec=DEFAULT_PRECISION):
	return [fp_vector(x,prec) for x in mat]

def retrieve_fp(scalar,prec=DEFAULT_PRECISION):
	return scalar/(2**prec)

def retrieve_fp_vector(vec,prec=DEFAULT_PRECISION):
	return [retrieve_fp(x,prec) for x in vec]

def retrieve_fp_matrix(mat,prec=DEFAULT_PRECISION):
	return [retrieve_fp_vector(x,prec) for x in mat]

def off_gen(pubkey, tx, usk):
	return pubkey.offline_gen_secret(tx,usk)

def off_gen_vec(pubkey, tx, usk):
	size = np.shape(tx)
	if len(size) == 1:
		return [pubkey.offline_gen_secret(y,usk) for y in tx]
	else:
		return pubkey.offline_gen_secret(tx,usk)

def off_gen_mat(pubkey, tx, usk):
	size = np.shape(tx)
	if len(size) == 2:
		return [[pubkey.offline_gen_secret(y,usk) for y in z] for z in tx]
	else:
		if len(size) == 1:
			return [pubkey.offline_gen_secret(y,usk) for y in tx]
		else:
			return pubkey.offline_gen_secret(tx,usk)
	# mat = np.array([[pubkey.offline_gen_secret(y,usk) for y in z] for z in tx])
	# mat = mat.astype(int)
	# return mat

def on_enc(pubkey, x, sx, enc_sx = None):
	if enc_sx is None and not isinstance(sx,paillier.EncryptedNumber):
		return pubkey.encrypt(x,sx)
	else:
		return pubkey.encrypt(x,sx,enc_sx)

def on_enc_vec(pubkey, x, sx, enc_sx = None):
	size = np.shape(x)
	if len(size) == 1:
		if enc_sx is None and not isinstance(sx,paillier.EncryptedNumber):
			return [pubkey.encrypt(x[i],sx[i]) for i in range(size[0])]
		else:
			return [pubkey.encrypt(x[i],sx[i],enc_sx[i]) for i in range(size[0])]
	else:
		return pubkey.encrypt(x,sx,enc_sx)

def on_enc_mat(pubkey, x, sx, enc_sx = None):
	size = np.shape(x)
	print(type(x[0][0]),type(sx[0][0]),type(enc_sx[0][0]))
	if len(size) == 2:
		if enc_sx is None and not isinstance(sx,paillier.EncryptedNumber):
			return [[pubkey.encrypt(x[i][j],sx[i][j]) for j in range(size[1])] for i in range(size[0])]
		else:
			return [[pubkey.encrypt(x[i][j],sx[i][j],enc_sx[i][j]) for j in range(size[1])] for i in range(size[0])]
	else:
		if len(size) == 1:
			return on_enc_vec(pubkey, x, sx, enc_sx)
		else:
			return pubkey.encrypt(x,sx,enc_sx)

def on_dec(privkey, x, sx=None):
	if sx is None:
		return privkey.decrypt(x)
	else:
		return privkey.decrypt(x,sx) 

def on_dec_vec(privkey, x, sx=None):
	if sx is None:
		return [privkey.decrypt(x[i]) for i in range(len(x))]
	else:
		return [privkey.decrypt(x[i],sx[i]) for i in range(len(x))]

def on_dec_mat(privkey, x, sx=None):
	if sx is None:
		return [[privkey.decrypt(x[i][j]) for j in range(len(x[0]))] for i in range(len(x))]
	else:
		return [[privkey.decrypt(x[i][j],sx[i][j]) for j in range(len(x[0]))] for i in range(len(x))]

### Vectorize returns everything as np.ndarray

vfp = np.vectorize(fp)
vretrieve_fp = np.vectorize(retrieve_fp)
voff_gen = np.vectorize(off_gen)
vencrypt = np.vectorize(encrypt)
von_enc = np.vectorize(on_enc)
von_dec = np.vectorize(on_dec)





def convert_to_json_serializable(obj):

	
    from gmpy2 import mpz
    # Delayed imports avoid circular issues
    try:
        from paillier import EncryptedNumber
    except ImportError:
        EncryptedNumber = None
    try:
        from labhe import LabEncryptedNumber
    except ImportError:
        LabEncryptedNumber = None

 

    if isinstance(obj, mpz):
        return int(obj)
    
    elif isinstance(obj, EncryptedNumber):
        return {
            "__EncryptedNumber__": True,
            "ciphertext": int(obj.ciphertext(be_secure=False))  # Use method, not attribute
        }
    
    elif isinstance(obj, LabEncryptedNumber):
        ct = obj.ciphertext
        if isinstance(ct, tuple):
            return {
                "__LabEncryptedNumber__": True,
                "ciphertext": [int(ct[0]), convert_to_json_serializable(ct[1])]
            }
        else:
            return {
                "__LabEncryptedNumber__": True,
                "ciphertext": convert_to_json_serializable(ct)
            }
    
    elif isinstance(obj, dict):
        return {k: convert_to_json_serializable(v) for k, v in obj.items()}
    
    elif isinstance(obj, list):
        return [convert_to_json_serializable(x) for x in obj]
    
    elif isinstance(obj, tuple):
        return tuple(convert_to_json_serializable(x) for x in obj)
    
    elif isinstance(obj, (int, float, str, bool)) or obj is None:
        return obj
    
    else:
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
	
from functools import reduce
import operator

def mul_sc_encrypted_vectors(x, y):
    return [x[i] * y[i] for i in range(len(x))]

def dot_sc_encrypted_vectors(x, y):
    if len(x) != len(y):
        raise ValueError(f"Length mismatch in dot product: len(x) = {len(x)}, len(y) = {len(y)}")
    return reduce(operator.add, mul_sc_encrypted_vectors(x, y))

def dot_m_encrypted_vectors(enc_vec, plain_mat):

    result = []
    for row in plain_mat:
        if len(row) != len(enc_vec):
            raise ValueError("Row length does not match enc_vec length")
        dot = None
        for e, a in zip(enc_vec, row):
            prod = e * a 
            dot = prod if dot is None else dot + prod
        result.append(dot)
    return result



def clamp_scalar(val, max_abs_val):
    #Clamp value to the LabHE-supported range [-max_abs_val, max_abs_val].
    if val > max_abs_val:
        return max_abs_val
    elif val < -max_abs_val:
        return -max_abs_val
    return val


def fp_encode(val, lf):
    #Fixed-point encode a float with given scaling factor lf
    return int(round(val * (1 << lf)))

def fp_decode(val, lf):
    #Fixed-point decode an integer to float with given scaling factor lf
    return float(val) / (1 << lf)