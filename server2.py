#!/usr/bin/env python3

import socket
import sys,struct
import json
from gmpy2 import mpz, random_state, mpz_urandomb, powmod, t_mod_2exp, t_div_2exp
import paillier
from paillier import PaillierPublicKey,PaillierPrivateKey
from pathlib import Path
import numpy as np
import time
import DGK
import genDGK
import util_fpv
from util_fpv import clamp_scalar
import os
import labhe
from labhe import LabEncryptedNumber
import random


DEFAULT_KEYSIZE = 512						
DEFAULT_MSGSIZE = 64 						
DEFAULT_SECURITYSIZE = 100					
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE/2)	
DEFAULT_DGK = 160							
KEYSIZE_DGK = 512						
MSGSIZE_DGK = 20							
NETWORK_DELAY = 0 		

seed = 43	

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False


def encrypt_vector(pubkey, x, coins=None):
	if (coins==None):
		return [pubkey.encrypt(y) for y in x]
	else: return [pubkey.encrypt(y,coins.pop()) for y in x]

def encrypt_matrix(pubkey, x, coins=None):
	if (coins==None):
		return [[pubkey.encrypt(y) for y in z] for z in x]
	else: return [[pubkey.encrypt(y,coins.pop()) for y in z] for z in x]

def decrypt_vector(privkey, x):
    result = []
    for i in x:
        if hasattr(i, 'ciphertext'):  # Basic check for encrypted object
            result.append(privkey.decrypt(i))
        else:
            raise TypeError(f"Expected encrypted object, got {type(i)}: {i}")
    return np.array(result)


def sum_encrypted_vectors(x, y):
	return [x[i] + y[i] for i in range(np.size(x))]

def diff_encrypted_vectors(x, y):
	return [x[i] - y[i] for i in range(len(x))] 

def mul_sc_encrypted_vectors(x, y):
    return [y[i]*x[i] for i in range(len(x))]    

def dot_sc_encrypted_vectors(x, y): 
    return sum(mul_sc_encrypted_vectors(x,y))

def dot_m_encrypted_vectors(x, A):
    return [dot_sc_encrypted_vectors(x,vec) for vec in A]

def encrypt_vector_DGK(pubkey, x, coins=None):
	if (coins==None):
		return [pubkey.raw_encrypt(y) for y in x]
	else: return [pubkey.raw_encrypt(y,coins.pop()) for y in x]

def decrypt_vector_DGK(privkey, x):
    return np.array([privkey.raw_decrypt0(i) for i in x])

"""We take the convention that a number x < N/3 is positive, and that a number x > 2N/3 is negative. 
	The range N/3 < x < 2N/3 allows for overflow detection.""" 

def Q_s(scalar,prec=DEFAULT_PRECISION):
	return int(scalar*(2**prec))/(2**prec)

def Q_vector(vec,prec=DEFAULT_PRECISION):
	if np.size(vec)>1:
		return [Q_s(x,prec) for x in vec]
	else:
		return Q_s(vec,prec)

def Q_matrix(mat,prec=DEFAULT_PRECISION):
	return [Q_vector(x,prec) for x in mat]

def fp(val, lf=32, max_val=None):
    scale = 2 ** lf
    fixed = int(round(val * scale))
    if max_val is not None:
        return clamp_scalar(fixed, max_val)
    return fixed


def fp_vector(vec, lf=32, max_val=None):
    scale = 2 ** lf
    return [clamp_scalar(int(round(v * scale)), max_val) if max_val is not None else int(round(v * scale)) for v in vec]


def fp_matrix(mat,prec=DEFAULT_PRECISION):
	return [fp_vector(x,prec) for x in mat]

def retrieve_fp(scalar,prec=DEFAULT_PRECISION):
	return scalar/(2**prec)

def retrieve_fp_vector(vec,prec=DEFAULT_PRECISION):
	return [retrieve_fp(x,prec) for x in vec]

def retrieve_fp_matrix(mat,prec=DEFAULT_PRECISION):
	return [retrieve_fp_vector(x,prec) for x in mat]


class Server2:
    def __init__(self, l=DEFAULT_MSGSIZE, t_DGK=DEFAULT_DGK, sigma=DEFAULT_SECURITYSIZE):
        try:
            # Load Paillier public key
            filepub = f"Keys/pubkey{DEFAULT_KEYSIZE}.txt"
            with open(filepub, 'r') as fin:
                data = [line.split() for line in fin]
            Np = mpz(data[0][0])
            mpk = PaillierPublicKey(n=Np)
            pubkey = labhe.LabHEPublicKey(mpk)

            # Load Paillier private key
            filepriv = f"Keys/privkey{DEFAULT_KEYSIZE}.txt"
            with open(filepriv, 'r') as fin:
                data = [line.split() for line in fin]
            p = mpz(data[0][0])
            q = mpz(data[1][0])
            msk = PaillierPrivateKey(mpk, p, q)

            # Dummy upk used just to satisfy constructor — not used for decryption
            c0 = pubkey.Pai_key.encrypt(0)  # Paillier encryption of 0
            dummy_ciphertext = (c0, c0)      # LabHE expects a 2-element structure
            dummy_upk = [LabEncryptedNumber(pubkey, dummy_ciphertext)]

            privkey = labhe.LabHEPrivateKey(msk, dummy_upk)

            self.pubkey = pubkey
            self.privkey = privkey

        except Exception as e:
            print("Key loading failed. Generating new keys...", e)


            # Key generation fallback
            usk = [random.randint(1, 1000) for _ in range(1)]  # single usk
            self.pubkey, self.privkey = labhe.generate_LabHE_keypair(usk, n_length=DEFAULT_KEYSIZE)

            # Save new keys
            Np = self.pubkey.n
            os.makedirs("Keys", exist_ok=True)
            with open(f"Keys/pubkey{DEFAULT_KEYSIZE}.txt", 'w') as f:
                f.write(f"{Np}")
            with open(f"Keys/privkey{DEFAULT_KEYSIZE}.txt", 'w') as f:
                f.write(f"{self.privkey.msk.p}\n{self.privkey.msk.q}")



        self.N_len = Np.bit_length()
        self.l = l
        self.t_DGK = t_DGK
        self.sigma = sigma
        self.generate_DGK()

    def params(self, n, m, N, Kc, Kw, T):
        self.Kc = Kc
        self.Kw = Kw
        self.nc = m * N
        t2 = 2 * self.t_DGK
        random_gen = random_state(seed)

        pathP = Path(f'Randomness/{self.N_len}.txt')
        if pathP.is_file():
            with open(pathP) as file:
                coinsP = [int(next(file)) for _ in range(7*(T-1)*self.nc*Kw + 7*self.nc*Kc)]
        else:
            coinsP = [mpz_urandomb(random_gen, self.N_len - 1) for _ in range(7*(T-1)*self.nc*Kw + 7*self.nc*Kc)]
        self.coinsP = [powmod(x, self.pubkey.n, self.pubkey.nsquare) for x in coinsP]

        pathDGK = Path(f'Randomness/{t2}.txt')
        if pathDGK.is_file():
            with open(pathDGK) as file:
                coinsDGK = [int(next(file)) for _ in range(2*(self.l+1)*self.nc*Kc + 2*(self.l+1)*self.nc*Kw*(T-1))]
        else:
            coinsDGK = [mpz_urandomb(random_gen, t2) for _ in range(2*(self.l+1)*self.nc*Kc + 2*(self.l+1)*self.nc*Kw*(T-1))]
        self.coinsDGK = [powmod(self.DGK_pubkey.h, x, self.DGK_pubkey.n) for x in coinsDGK]

    def init_comparison_s2(self, msg):
        self.z = [mpz(x) for x in decrypt_vector(self.privkey, msg)]
        self.beta = []
        for x in self.z:
            bin_str = t_mod_2exp(x, self.l).digits(2)
            self.beta.append(bin_str.zfill(self.l))

    def generate_DGK(self):
        try:
            file = f'Keys/DGK_keys{KEYSIZE_DGK}_{MSGSIZE_DGK}.txt'
            p, q, u, vp, vq, fp, fq, g, h = DGK.loadkey(file)
        except:
            p, q, u, vp, vq, fp, fq, g, h = genDGK.keysDGK(KEYSIZE_DGK, MSGSIZE_DGK, self.t_DGK)
            os.makedirs("Keys", exist_ok=True)
            with open(f'Keys/DGK_keys{KEYSIZE_DGK}_{MSGSIZE_DGK}.txt', 'w') as f:
                f.write(f"{p}\n{q}\n{u}\n{vp}\n{vq}\n{fp}\n{fq}\n{g}\n{h}")

        n = p * q
        self.DGK_pubkey = DGK.DGKpubkey(n, g, h, u)
        self.DGK_privkey = DGK.DGKprivkey(p, q, vp, self.DGK_pubkey)

    def DGK_s2(self, c_all):
        self.delta_B = []
        for c in c_all:
            flag = any(int(self.DGK_privkey.raw_decrypt0(bit)) == 0 for bit in c)
            self.delta_B.append(int(flag))

        db = encrypt_vector(self.pubkey, self.delta_B, self.coinsP[-self.nc:])
        z = encrypt_vector(self.pubkey, [mpz(t_div_2exp(self.z[i], self.l)) for i in range(self.nc)], self.coinsP[-2*self.nc:-self.nc])
        self.coinsP = self.coinsP[:-2*self.nc]
        return db, z

    def choose_max(self, a, b):
        return [
            a[i] + self.pubkey.encrypt(0, self.coinsP.pop()) if int(self.t_comp[i]) == 0
            else b[i] + self.pubkey.encrypt(0, self.coinsP.pop())
            for i in range(self.nc)
        ]

    def choose_min(self, a, b):
        return [
            a[i] + self.pubkey.encrypt(0, self.coinsP.pop()) if int(self.t_comp[i]) == 1
            else b[i] + self.pubkey.encrypt(0, self.coinsP.pop())
            for i in range(self.nc)
        ]


def keys(DGK_pubkey):
	pubkeys = {}
	pubkeys['public_key_DGK'] = {'n': int(DGK_pubkey.n), 'g':int(DGK_pubkey.g),'h':int(DGK_pubkey.h), 'u':int(DGK_pubkey.u)}
	serialized_pubkeys = json.dumps(pubkeys)
	return serialized_pubkeys

def get_enc_data(received_list, pubkey):
    result = []
    for x in received_list:
        if isinstance(x, (list, tuple)) and len(x) == 2:
            # LabHE ciphertext: (c0, c1)
            c0, c1 = int(x[0]), int(x[1])
            result.append(labhe.LabEncryptedNumber(pubkey, (c0, c1)))
        elif isinstance(x, int):
            # Paillier-style ciphertext, treated as rerandomized (only c0)
            result.append(labhe.LabEncryptedNumber(pubkey, (int(x),)))  # single-element tuple
        else:
            raise TypeError(f"Invalid ciphertext format: expected (c0, c1) or int, got {x}")
    return result



def get_plain_data(data):
    result = []
    for x in data:
        try:
            result.append(int(x))
        except (ValueError, TypeError):
            print(f"Warning: could not convert {x} to int")
    return result


def recv_size(the_socket):
	#data length is 4 bytes
	total_len=0;total_data=[];size=sys.maxsize
	size_data=sock_data=bytes([]);recv_size= 4096 
	while total_len<size:
		sock_data=the_socket.recv(recv_size)
		if not total_data:
			if len(sock_data)>4:
				size=struct.unpack('>i', sock_data[:4])[0]
				recv_size=size
				if recv_size>262144:recv_size=262144
				total_data.append(sock_data[4:])
			else:
				size_data+=sock_data

		else:
			total_data.append(sock_data)
		total_len=sum([len(i) for i in total_data ])
	return b''.join(total_data)

def send_encr_data(encrypted_number_list):
	time.sleep(NETWORK_DELAY)
	encrypted = {}
	encrypted = [str(x.ciphertext()) for x in encrypted_number_list]
	return json.dumps(encrypted)

def send_DGK_data(encrypted_number_list):
	time.sleep(NETWORK_DELAY)
	encrypted = {}
	encrypted = [str(x) for x in encrypted_number_list]
	return json.dumps(encrypted)

def send_DGK_matrix(encrypted_number_list):
	time.sleep(NETWORK_DELAY)
	encrypted = {}
	encrypted = [[str(y) for y in x] for x in encrypted_number_list]
	return json.dumps(encrypted)

def get_DGK_data(received_dict):
	return [mpz(x) for x in received_dict]

def get_DGK_matrix(received_dict):
	return [[mpz(y) for y in x] for x in received_dict]

def main():
	
	lf = DEFAULT_PRECISION
	s2 = Server2()
	l = s2.l
	pubkey = s2.pubkey
	privkey = s2.privkey
	DGK_pubkey = s2.DGK_pubkey
	serialized_pubkey = keys(DGK_pubkey)

	# TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print('Server2: Socket successfully created')
	port = 10000
	# Bind the socket to the port
	localhost = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
	server_address = (localhost, port)
	print('Server2: Starting up on {} port {}'.format(*server_address))
	sock.bind(server_address)


	sock.listen(1)      
	print('Server2: Socket is listening')
	connection, client_address = sock.accept()	
	try:
		print('Server2: Connection from', client_address)
		# data = recv_size(connection)
		data = json.loads(recv_size(connection))
		if data:
			n,m,N,Kc,Kw,T = get_plain_data(data)
			s2.params(n,m,N,Kc,Kw,T)
			nc = m*N
			K = Kc
			# Send DGK public key
			connection.sendall(struct.pack('>i', len(serialized_pubkey))+serialized_pubkey.encode('utf-8'))		
			for i in range(0,T):
				for k in range(0,K):
					# Receive temp_t + r
					data = json.loads(recv_size(connection))
					temp_tr = get_enc_data(data,pubkey)
					temp_tr = decrypt_vector(privkey,temp_tr)
					temp_tr = fp_vector(temp_tr,-2*lf)
					temp_tr = encrypt_vector(s2.pubkey,temp_tr,s2.coinsP[-nc:])
					s2.coinsP = s2.coinsP[:-nc]
					# Send temp_tr
					serialized_data = send_encr_data(temp_tr)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))

					# Projection on hu
					s2.delta_B = [0]*nc
					# Receive z_DGK
					data = json.loads(recv_size(connection))
					z_DGK = get_enc_data(data,pubkey)
					s2.init_comparison_s2(z_DGK)
					s2.coinsDGK = s2.coinsDGK[:-nc]
					b = [[0]*l]*nc
					b = [encrypt_vector_DGK(DGK_pubkey,[int(s2.beta[i][j]) for j in range(0,l)],s2.coinsDGK[-(i+1)*l:-i*l] or s2.coinsDGK[-l:]) for i in range(0,nc)]
					s2.coinsDGK = s2.coinsDGK[:-l*nc]
					# Send b = bits of beta
					serialized_data = send_DGK_matrix(b)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))
					# Receive c
					data = json.loads(recv_size(connection))
					c = get_DGK_matrix(data)
					delta_B, zdivl = s2.DGK_s2(c)
					# Send delta_B, zdivl
					serialized_data = send_encr_data(delta_B+zdivl)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))
					# Receive t,a2,bs
					data = json.loads(recv_size(connection))
					merged = get_enc_data(data,pubkey)
					t_comp = merged[:nc]; a2 = merged[nc:2*nc]; b2 = merged[2*nc:]
					s2.t_comp = decrypt_vector(s2.privkey,t_comp)
					v = s2.choose_min(a2,b2)
					# Send v
					serialized_data = send_encr_data(v)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))

					# Projection on lu
					s2.delta_B = [0]*nc
					# Receive z_DGK
					data = json.loads(recv_size(connection))
					z_DGK = get_enc_data(data,pubkey)
					s2.init_comparison_s2(z_DGK)
					b = [[0]*l]*nc
					b = [encrypt_vector_DGK(DGK_pubkey,[int(s2.beta[i][j]) for j in range(0,l)],s2.coinsDGK[-(i+1)*l:-i*l] or s2.coinsDGK[-l:]) for i in range(0,nc)]
					s2.coinsDGK = s2.coinsDGK[:-l*nc]
					# Send b
					serialized_data = send_DGK_matrix(b)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))
					# Receive c
					data = json.loads(recv_size(connection))
					c = get_DGK_matrix(data)
					delta_B, zdivl = s2.DGK_s2(c)
					# Send delta_B, zdivl
					serialized_data = send_encr_data(delta_B+zdivl)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))
					# Receive t,a2,bs
					data = json.loads(recv_size(connection))
					merged = get_enc_data(data,pubkey)
					t_comp = merged[:nc]; a2 = merged[nc:2*nc]; b2 = merged[2*nc:]
					s2.t_comp = decrypt_vector(s2.privkey,t_comp)
					v = s2.choose_max(a2,b2)
					# Send v
					serialized_data = send_encr_data(v)
					connection.sendall(struct.pack('>i', len(serialized_data))+serialized_data.encode('utf-8'))

					K = Kw				


	finally:
		print('Server2: Closing socket')
		connection.close()				

if __name__ == '__main__':
	main()