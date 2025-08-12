#!/usr/bin/env python3

import socket
import sys,struct
import json
from gmpy2 import mpz, random_state, mpz_urandomb, powmod
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

DEFAULT_KEYSIZE = 512					        
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


import time
import json
import numbers
try:
    from gmpy2 import mpz as _mpz_type
except Exception:
    _mpz_type = None

def send_encr_data(encrypted_number_list):
    """
    Serialize a list of LabEncryptedNumber into JSON-ready list of [c0, c1] string pairs.
    """
    time.sleep(NETWORK_DELAY)
    out = []

    for x in encrypted_number_list:
        if not isinstance(x, labhe.LabEncryptedNumber):
            raise TypeError(f"Expected LabEncryptedNumber, got {type(x)}")

        c0, c1 = x.ciphertext  # LabHE ciphertext is a tuple
        out.append([str(c0), str(c1)])

    return json.dumps(out)


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


import json
import ast
try:
    from gmpy2 import mpz as _mpz_type
except Exception:
    _mpz_type = None


def get_enc_data(received_json, pubkey):
    """
    Parse JSON from send_encr_data and return list of LabEncryptedNumber.
    """
    if isinstance(received_json, str):
        data = json.loads(received_json)
    else:
        data = received_json

    result = []
    for item in data:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            c0 = int(item[0])
            c1 = int(item[1])
            result.append(labhe.LabEncryptedNumber(pubkey, (c0, c1)))
        else:
            raise ValueError("Expected list of [c0, c1] for each ciphertext.")
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
    pubkey = client.pubkey  # LabHE public key
    print("DEBUG: Public key type =", type(pubkey))

    privkey = client.privkey

    # TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Client: Socket successfully created')
    port = 10000
    localhost = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                              if not ip.startswith("127.")][:1],
                              [[(s.connect(('8.8.8.8', 53)),
                                 s.getsockname()[0], s.close())
                                for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    server_address = (localhost, port)
    print('Client: Starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)
    print('Client: Socket is listening')
    connection, client_address = sock.accept()

    try:
        print('Client: Connection from', client_address)
        data = json.loads(recv_size(connection))
        if data:
            # Receive n,m,N,K,T
            n, m, N, Kc, Kw, T = get_plain_data(data)
            client.n = n
            client.m = m
            client.N = N
            client.Kc = Kc
            client.Kw = Kw
            client.T = T
            nc = m * N
            client.nc = nc

            client.gen_rands()
            client.load_data(n, m, N)

            fileA = f"Data/A{n}_{m}_{N}.txt"
            A = np.loadtxt(fileA, delimiter=',')
            fileB = f"Data/B{n}_{m}_{N}.txt"
            B = np.loadtxt(fileB, delimiter=',')

            x = [[0] * n] * (T + 1)
            u = [[0] * m] * T
            x[0] = client.x0

            start = time.time()
            sec = [0] * T
            K = Kc
            time_client = [0] * K
            time_cloud = [0] * K

            for i in range(0, T):
                # Encrypt x[i] with fixed-point encoding (LabHE)
                fixed_x = fp_vector(x[i], lf)
                secret = pubkey.offline_gen_secret(label=..., usk=...)  # TODO: provide real label and usk
                enc_x0 = [
                    pubkey.encrypt_with_label(int(val), secret, r_value=r_value)
                    for val, r_value in zip(fixed_x, client.coinsP[-n:])
                ]
                client.coinsP = client.coinsP[:-n]

                # Send [[x0]]
                data = send_encr_data(enc_x0)
                connection.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                time_x0 = time.time() - start

                start_cloud = time.time()
                for k in range(0, K):
                    # Receive [[t_k]]
                    data = json.loads(recv_size(connection))
                    time_cloud[k] = time.time() - start_cloud
                    start_tk = time.time()

                    enc_t = get_enc_data(data, pubkey)
                    t = retrieve_fp_vector(decrypt_vector(privkey, enc_t), 3 * lf)

                    # Compare and encrypt U (LabHE)
                    U = client.compare(t)
                    fixed_U = fp_vector(U, lf)
                    secret = pubkey.offline_gen_secret(label=..., usk=...)  # TODO: provide real label and usk
                    enc_U = [
                        pubkey.encrypt_with_label(int(val), secret, r_value=r_value)
                        for val, r_value in zip(fixed_U, client.coinsP[-nc:])
                    ]
                    client.coinsP = client.coinsP[:-nc]

                    # Send [[U_{k+1}]]
                    data = send_encr_data(enc_U)
                    connection.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                    time_client[k] = time.time() - start_tk
                    start_cloud = time.time()

                K = Kw
                u[i] = Q_vector(U[:m])
                print("Last input: ", ["%.8f" % val for val in u[i]])
                x[i + 1] = np.dot(A, x[i]) + np.dot(B, u[i])
                print("Next state: ", ["%.8f" % val for val in x[i + 1]])
                sec[i] = time.time() - start
                start = time.time()

            print(sec)
            with open(os.path.abspath(f"{DEFAULT_KEYSIZE}_{lf}_results_CS.txt"), 'a+') as f:
                f.write(f"{n}, {m}, {N}, {Kc}, {Kw}, {T}: ")
                for item in sec:
                    f.write(f"total time {item:.2f} ")
                f.write("\n")
                f.write(f"avg. time FGM iteration for client: {np.mean(time_client):.3f}\n")
                f.write(f"avg. time FGM iteration for cloud: {np.mean(time_cloud):.3f}\n")

    finally:
        print('Client: Closing connection')
        connection.close()


if __name__ == '__main__':
    main()
