#!/usr/bin/env python3

import socket
import sys,struct
import json
from gmpy2 import mpz
import paillier
from paillier import PaillierPublicKey,PaillierPrivateKey
import numpy as np
import time
import random
import os
import util_fpv 
from util_fpv import clamp_scalar
import labhe
try:
	import gmpy2
	HAVE_GMP = True
except ImportError:
	HAVE_GMP = False

DEFAULT_KEYSIZE = 1024					        
DEFAULT_MSGSIZE = 64 					    
DEFAULT_SECURITYSIZE = 100				        
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE/2)     
NETWORK_DELAY = 0

seed = 42	
def encrypt_vector(pubkey, x, coins=None):
    if coins is None:
        return [pubkey.encrypt(y) for y in x]
    else:
        return [pubkey.encrypt(y, coins.pop()) for y in x]

def decrypt_vector(privkey, x):
    result = []
    for i in x:
        if isinstance(i, labhe.LabEncryptedNumber):
            result.append(privkey.decrypt(i))
        elif isinstance(i, paillier.EncryptedNumber):
            result.append(privkey.msk.decrypt(i))
        else:
            raise TypeError(f"Unknown encryption type: {type(i)}")
    return np.array(result)

    



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


def retrieve_fp(scalar,prec=DEFAULT_PRECISION):
	return scalar/(2**prec)

def retrieve_fp_vector(vec,prec=DEFAULT_PRECISION):
	return [retrieve_fp(x,prec) for x in vec]

import os
import random
import numpy as np
from gmpy2 import mpz, random_state, mpz_urandomb, powmod
from paillier import PaillierPublicKey
import labhe

DEFAULT_KEYSIZE = 512
DEFAULT_MSGSIZE = 10
seed = 42 



class Client:
    def __init__(self, l=DEFAULT_MSGSIZE):
        self.l = l
        try:
            # Load public key
            filepub = f"Keys/pubkey{DEFAULT_KEYSIZE}.txt"
            with open(filepub, 'r') as fin:
                data = [line.split() for line in fin]
                Np = int(data[0][0])

            mpk = PaillierPublicKey(n=Np)
            pubkey = labhe.LabHEPublicKey(mpk)

            # Load private key
            filepriv = f"Keys/privkey{DEFAULT_KEYSIZE}.txt"
            with open(filepriv, 'r') as fin:
                data = [line.split() for line in fin]
                p = mpz(data[0][0])
                q = mpz(data[1][0])

            pai_priv = PaillierPrivateKey(mpk, p, q)

            # Generate dummy usk and upk
            usk = [random.randint(1, 1000) for _ in range(5)]
            upk = util_fpv.encrypt_vector(mpk, usk)  
            privkey = labhe.LabHEPrivateKey(pai_priv, upk)

            self.pubkey = pubkey
            self.privkey = privkey

        except Exception as e:
            print("Key loading failed. Generating new keys...", e)
            usk = [random.randint(1, 1000) for _ in range(5)]
            self.pubkey, self.privkey = labhe.generate_LabHE_keypair(usk, n_length=DEFAULT_KEYSIZE)

            # Save keys to disk
            Np = self.pubkey.n
            os.makedirs("Keys", exist_ok=True)
            with open(f"Keys/pubkey{DEFAULT_KEYSIZE}.txt", 'w') as f:
                f.write(f"{Np}")
            with open(f"Keys/privkey{DEFAULT_KEYSIZE}.txt", 'w') as f:
                f.write(f"{self.privkey.msk.p}\n{self.privkey.msk.q}")



    def load_data(self, n, m, N):
        fileparam = f"Data/x0{n}_{m}_{N}.txt"
        self.x0 = np.loadtxt(fileparam)

        filew0 = f"Data/w0{n}_{m}_{N}.txt"
        w0 = np.loadtxt(filew0, delimiter=',')

        hu = np.concatenate([w0[2 * i * m:(2 * i + 1) * m] for i in range(N)])
        lu = np.concatenate([-w0[(2 * i + 1) * m:2 * (i + 1) * m] for i in range(N)])
        self.hu = hu
        self.lu = lu

    def gen_rands(self):
        n = self.n
        Kc = self.Kc
        Kw = self.Kw
        nc = self.nc
        T = self.T

        N_len = self.pubkey.n.bit_length()
        state = random_state(seed)
        total_rands = T * n + (T - 1) * nc * Kw + nc * Kc
        coinsP = [mpz_urandomb(state, N_len - 1) for _ in range(total_rands)]
        self.coinsP = [powmod(x, self.pubkey.n, self.pubkey.nsquare) for x in coinsP]

    def compare(self, t):
        nc = self.nc
        with np.errstate(invalid='ignore'):
            U = np.maximum(self.lu, np.minimum(self.hu, t))
        return U


def send_encr_data(encrypted_number_list):
	time.sleep(NETWORK_DELAY)
	enc_with_one_pub_key = {}
	enc_with_one_pub_key = [str(x.ciphertext()) for x in encrypted_number_list]
	return json.dumps(enc_with_one_pub_key)

def send_plain_data(data):
	time.sleep(NETWORK_DELAY)
	return json.dumps([str(x) for x in data])

def recv_size(the_socket):
	#data length packed into 4 bytes
	total_len=0;total_data=[];size=sys.maxsize
	size_data=sock_data=bytes([]);recv_size=4096
	while total_len<size:
		sock_data=the_socket.recv(recv_size)
		if not total_data:
			if len(sock_data)>4:
				size=struct.unpack('>i', sock_data[:4])[0]
				recv_size=size
				if recv_size>4096:recv_size=4096
				total_data.append(sock_data[4:])
			else:
				size_data+=sock_data

		else:
			total_data.append(sock_data)
		total_len=sum([len(i) for i in total_data ])
	return b''.join(total_data)
def get_enc_data(received_list, pubkey):
    result = []
    for x in received_list:
        if isinstance(x, (list, tuple)) and len(x) == 2:

            c0, c1 = int(x[0]), int(x[1])
            result.append(labhe.LabEncryptedNumber(pubkey, (c0, c1)))
        elif isinstance(x, (int, str)):
          
            c0 = int(x)
            result.append(labhe.LabEncryptedNumber(pubkey, (c0, 0)))
        else:
            raise TypeError(f"Unsupported encrypted input: {x}")
    return result



def get_plain_data(data):
    result = []
    for x in data:
        try:
            result.append(int(x))
        except (ValueError, TypeError):
            print(f"Warning: could not convert {x} to int")
    return result



def main():

	
	lf = DEFAULT_PRECISION
	client = Client()
	pubkey = client.pubkey
	privkey = client.privkey

	# TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print('Client: Socket successfully created')
	port = 10000
	# Bind the socket to the port
	localhost = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
	server_address = (localhost, port)
	print('Client: Starting up on {} port {}'.format(*server_address))
	sock.bind(server_address)

	# Listen for incoming connections
	sock.listen(1)      
	print('Client: Socket is listening')
	connection, client_address = sock.accept()	
	try:
		print('Client: Connection from', client_address)
		# data = recv_size(connection)
		data = json.loads(recv_size(connection))
		if data:	
			# Receive n,m,N,K,T
			n,m,N,Kc,Kw,T = get_plain_data(data)
			client.n = n; client.m = m; client.N = N; client.Kc = Kc; client.Kw = Kw; client.T = T
			nc = m*N; client.nc = nc
			client.gen_rands()
			client.load_data(n,m,N)
			fileA = "Data/A"+str(n)+"_"+str(m)+"_"+str(N)+".txt"
			A = np.loadtxt(fileA, delimiter=',')
			fileB = "Data/B"+str(n)+"_"+str(m)+"_"+str(N)+".txt"
			B = np.loadtxt(fileB, delimiter=',')	
			x = [[0]*n]*(T+1)
			u = [[0]*m]*T
			x[0] = client.x0;

			start = time.time()
			sec = [0]*T
			K = Kc
			time_client = [0]*K
			time_cloud = [0]*K

			for i in range(0,T):
				enc_x0 = encrypt_vector(pubkey,fp_vector(x[i]),client.coinsP[-n:])
				client.coinsP = client.coinsP[:-n]
				# Send [[x0]]
				data = send_encr_data(enc_x0)
				connection.sendall(struct.pack('>i', len(data))+data.encode('utf-8'))
				time_x0 = time.time() - start
				start_cloud = time.time()
				for k in range(0,K):
					# Receive [[t_k]]
					data = json.loads(recv_size(connection))
					time_cloud[k] = time.time() - start_cloud
					start_tk = time.time()
					enc_t = get_enc_data(data,pubkey)
					t = retrieve_fp_vector(decrypt_vector(privkey,enc_t),3*lf)
					U = client.compare(t)
					enc_U = encrypt_vector(pubkey,fp_vector(U),client.coinsP[-nc:])
					client.coinsP = client.coinsP[:-nc]
					# Send [[U_{k+1}]]
					data = send_encr_data(enc_U)
					connection.sendall(struct.pack('>i', len(data))+data.encode('utf-8'))
					time_client[k] = time.time() - start_tk
					start_cloud = time.time()
				K = Kw
				u[i] = Q_vector(U[:m])
				print("Last input: ", ["%.8f"% i for i in u[i]])
				x[i+1] = np.dot(A,x[i]) + np.dot(B,u[i])
				print("Next state: ", ["%.8f"% i for i in x[i+1]])
				sec[i] = time.time() - start
				start = time.time()

			print(sec)
			with open(os.path.abspath(str(DEFAULT_KEYSIZE)+'_'+str(lf)+'_results_CS'+'.txt'),'a+') as f: 
				f.write("%d, %d, %d, %d, %d, %d: " % (n,m,N,Kc,Kw,T));
				for item in sec:
  					f.write("total time %.2f " % item)
				f.write("\n")
				f.write("avg. time FGM iteration for client: %.3f\n" % np.mean(time_client))
				f.write("avg. time FGM iteration for cloud: %.3f\n" % np.mean(time_cloud))




	finally:
		print('Client: Closing connection')
		connection.close()


if __name__ == '__main__':
	main()