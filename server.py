#!/usr/bin/env python3

import socket
import sys, struct
import json
from gmpy2 import mpz
import paillier
import numpy as np
import time
import random
try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

DEFAULT_KEYSIZE = 512
DEFAULT_MSGSIZE = 64
DEFAULT_SECURITYSIZE = 100
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE / 2)
NETWORK_DELAY = 0
seed = 42

def encrypt_vals(pubkey, vals, coins=None):
    if coins is None:
        print("[DEBUG] Encrypting values without coins...")
        return [pubkey.encrypt(v) for v in vals]
    else:
        print("[DEBUG] Encrypting values with coins...")
        return [pubkey.encrypt(v, coins.pop()) for v in vals]

def add_encrypted_vectors(vec1, vec2):
    return [vec1[i] + vec2[i] for i in range(np.size(vec1))]

def quant_scalar(val, precision=DEFAULT_PRECISION):
    return int(val * (2 ** precision)) / (2 ** precision)

def quant_vector(vec, precision=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [quant_scalar(v, precision) for v in vec]
    else:
        return quant_scalar(vec, precision)

def quant_matrix(mat, precision=DEFAULT_PRECISION):
    return [quant_vector(row, precision) for row in mat]

def fixed_point_scalar(val, precision=DEFAULT_PRECISION):
    return mpz(val * (2 ** precision))

def fixed_point_vector(vec, precision=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [fixed_point_scalar(v, precision) for v in vec]
    else:
        return fixed_point_scalar(vec, precision)

def fixed_point_matrix(mat, precision=DEFAULT_PRECISION):
    return [fixed_point_vector(row, precision) for row in mat]

def retrieve_fixed_point(val, precision=DEFAULT_PRECISION):
    return val / (2 ** precision)

def retrieve_fixed_point_vector(vec, precision=DEFAULT_PRECISION):
    return [retrieve_fixed_point(v, precision) for v in vec]

def retrieve_fixed_point_matrix(mat, precision=DEFAULT_PRECISION):
    return [retrieve_fixed_point_vector(row, precision) for row in mat]

def decrypt_vals(privkey, encrypted_vec):
    print("[DEBUG] Decrypting encrypted vector...")
    return np.array([privkey.decrypt(enc_val) for enc_val in encrypted_vec])


class Server:
    def __init__(self, n, m, N, l=DEFAULT_MSGSIZE, sigma=DEFAULT_KEYSIZE):
        print(f"[DEBUG] Initializing Server with n={n}, m={m}, N={N}")
        pubfile = f"Keys/pubkey{DEFAULT_KEYSIZE}.txt"
        with open(pubfile, 'r') as f:
            data = [line.split() for line in f]
        Np = mpz(data[0][0])
        self.pubkey = paillier.PaillierPublicKey(n=Np)

        fileH = f"Data/H{n}_{m}_{N}.txt"
        fileF = f"Data/F{n}_{m}_{N}.txt"
        fileG0 = f"Data/G0{n}_{m}_{N}.txt"
        fileK = f"Data/K{n}_{m}_{N}.txt"

        self.H = np.loadtxt(fileH, delimiter=',')
        self.F = np.loadtxt(fileF, delimiter=',')
        self.G0 = np.loadtxt(fileG0, delimiter=',')
        K = np.loadtxt(fileK, delimiter=',')
        self.Kc = int(K[0])
        self.Kw = int(K[1])
        self.nc = m * N

        Hq = quant_matrix(self.H)
        eigs = np.linalg.eigvals(Hq)
        L = np.real(max(eigs))
        mu = np.real(min(eigs))
        cond = quant_scalar(L / mu)
        self.eta = quant_scalar((np.sqrt(cond) - 1) / (np.sqrt(cond) + 1))
        self.Hf = quant_matrix([[h / quant_scalar(L) for h in row] for row in Hq])

        Ft = self.F.transpose()
        Ff = quant_matrix([[quant_scalar(h) / quant_scalar(L) for h in row] for row in Ft])
        self.mFft = fixed_point_matrix(np.negative(Ff), 2 * DEFAULT_PRECISION)

        coeff_z_mat = np.eye(self.nc) - self.Hf
        self.coeff_z = fixed_point_matrix(coeff_z_mat)

        print("[DEBUG] Server initialized with parameters set.")

    def compute_coeff(self, x0):
        print("[DEBUG] Computing coefficient vector coeff_0...")
        self.coeff_0 = np.dot(self.mFft, x0)

    def t_iterate(self, z):
        print("[DEBUG] Computing t iteration...")
        return add_encrypted_vectors(np.dot(self.coeff_z, z), self.coeff_0)

    def z_iterate(self, new_U, U):
        print("[DEBUG] Computing z iteration...")
        new_z_part = [fixed_point_scalar(1 + self.eta) * v for v in new_U]
        z_part = [fixed_point_scalar(-self.eta) * v for v in U]
        return add_encrypted_vectors(new_z_part, z_part)


def send_encrypted_list(enc_list):
    time.sleep(NETWORK_DELAY)
    enc_as_str = [str(x.ciphertext()) for x in enc_list]
    print(f"[DEBUG] Sending encrypted list of length {len(enc_as_str)}")
    return json.dumps(enc_as_str)

def send_plain_list(data_list):
    time.sleep(NETWORK_DELAY)
    print(f"[DEBUG] Sending plain list of length {len(data_list)}")
    return json.dumps([str(x) for x in data_list])

def receive_data_with_size(sock):
    total_len = 0
    data_chunks = []
    expected_size = sys.maxsize
    size_data = b''
    recv_chunk_size = 4096

    while total_len < expected_size:
        chunk = sock.recv(recv_chunk_size)
        if not data_chunks:
            if len(chunk) > 4:
                expected_size = struct.unpack('>i', chunk[:4])[0]
                recv_chunk_size = expected_size
                if recv_chunk_size > 4096:
                    recv_chunk_size = 4096
                data_chunks.append(chunk[4:])
            else:
                size_data += chunk
        else:
            data_chunks.append(chunk)
        total_len = sum(len(c) for c in data_chunks)
    full_data = b''.join(data_chunks)
    print(f"[DEBUG] Received data of length {len(full_data)} bytes")
    return full_data

def parse_encrypted_data(enc_data_list, pubkey):
    print(f"[DEBUG] Parsing encrypted data list of length {len(enc_data_list)}")
    return [paillier.EncryptedNumber(pubkey, int(x)) for x in enc_data_list]


def main():
    lf = DEFAULT_PRECISION
    n, m, N = 5, 5, 7
    T = 1
    print("[DEBUG] Starting server main function...")
    server = Server(n, m, N)
    server.Kc = 50
    server.Kw = 20
    Kc, Kw = server.Kc, server.Kw
    nc = server.nc
    m = server.m if hasattr(server, 'm') else m
    pubkey = server.pubkey
    U = [0] * nc

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 10000

    localhost = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                            if not ip.startswith("127.")][:1],
                             [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close())
                               for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]])
                 if l][0][0]
    server_address = (localhost, port)
    print(f"[DEBUG] Server connecting to {server_address}")
    sock.connect(server_address)

    continue_loop = True
    start_time = time.time()
    try:
        while continue_loop:
            data_to_send = send_plain_list([n, m, N, Kc, Kw, T])
            sock.sendall(struct.pack('>i', len(data_to_send)) + data_to_send.encode('utf-8'))

            U = encrypt_vals(pubkey, fixed_point_vector(U))
            z = [u * (2 ** lf) for u in U]
            K = Kc

            for i in range(T):
                print(f"[DEBUG] Waiting for encrypted x0 at time step {i}...")
                raw_data = json.loads(receive_data_with_size(sock))
                x0_enc = parse_encrypted_data(raw_data, pubkey)
                server.compute_coeff(x0_enc)

                for k in range(K):
                    print(f"[DEBUG] Iteration k={k} of {K}")
                    t_val = server.t_iterate(z)
                    enc_t = send_encrypted_list(t_val)
                    sock.sendall(struct.pack('>i', len(enc_t)) + enc_t.encode('utf-8'))

                    recv_data = json.loads(receive_data_with_size(sock))
                    new_U = parse_encrypted_data(recv_data, pubkey)
                    z = server.z_iterate(new_U, U)
                    U = new_U

                U = list(U[m:]) + list([pubkey.encrypt(0)] * m)
                z = [el * (2 ** lf) for el in U]
                K = Kw
            continue_loop = False
        print(f"[DEBUG] Total elapsed time: {time.time() - start_time:.4f} seconds")
    finally:
        print("[DEBUG] Closing server socket.")
        sock.close()


if __name__ == "__main__":
    main()
