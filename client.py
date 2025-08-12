#!/usr/bin/env python3

import socket
import sys, struct
import json
from gmpy2 import mpz
import paillier
import numpy as np
import time
import random
import os

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

DEFAULT_KEYSIZE = 512                      # RSA modulus bits
DEFAULT_MSGSIZE = 64                       # Plaintext bits
DEFAULT_SECURITYSIZE = 100                 # One-time pad bits
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE/2) # Fractional bits
NETWORK_DELAY = 0                          # Network delay simulation

seed = 42  # Random seed


def encrypt_vals(pubkey, values, coins=None):
    if coins is None:
        encrypted = [pubkey.encrypt(v) for v in values]
    else:
        encrypted = [pubkey.encrypt(v, coins.pop()) for v in values]
    print(f"[DEBUG] Encrypted {len(encrypted)} values")
    return encrypted


def decrypt_vals(privkey, encrypted_values):
    decrypted = np.array([privkey.decrypt(c) for c in encrypted_values])
    print(f"[DEBUG] Decrypted {len(decrypted)} values")
    return decrypted


def quant_scalar(scalar, precision=DEFAULT_PRECISION):
    q = int(scalar * (2**precision)) / (2**precision)
    print(f"[DEBUG] Quantized scalar {scalar} to {q}")
    return q


def quant_vector(vector, precision=DEFAULT_PRECISION):
    if np.size(vector) > 1:
        qvec = [quant_scalar(x, precision) for x in vector]
    else:
        qvec = quant_scalar(vector, precision)
    print(f"[DEBUG] Quantized vector with size {np.size(vector)}")
    return qvec


def quant_matrix(matrix, precision=DEFAULT_PRECISION):
    qmat = [quant_vector(row, precision) for row in matrix]
    print(f"[DEBUG] Quantized matrix with {len(matrix)} rows")
    return qmat


def fixed_point_scalar(scalar, precision=DEFAULT_PRECISION):
    fp_val = mpz(scalar * (2**precision))
    print(f"[DEBUG] Fixed point scalar: {scalar} -> {fp_val}")
    return fp_val


def fixed_point_vector(vector, precision=DEFAULT_PRECISION):
    if np.size(vector) > 1:
        fp_vec = [fixed_point_scalar(x, precision) for x in vector]
    else:
        fp_vec = fixed_point_scalar(vector, precision)
    print(f"[DEBUG] Converted vector to fixed point with size {np.size(vector)}")
    return fp_vec


def retrieve_fixed_point(scalar, precision=DEFAULT_PRECISION):
    val = scalar / (2 ** precision)
    print(f"[DEBUG] Retrieved fixed point scalar: {scalar} -> {val}")
    return val


def retrieve_fixed_point_vector(vector, precision=DEFAULT_PRECISION):
    vals = [retrieve_fixed_point(x, precision) for x in vector]
    print(f"[DEBUG] Retrieved fixed point vector of size {len(vector)}")
    return vals


class Client:
    def __init__(self, l=DEFAULT_MSGSIZE):
        try:
            pub_file = f"Keys/pubkey{DEFAULT_KEYSIZE}.txt"
            with open(pub_file, 'r') as fpub:
                data = [line.split() for line in fpub]
            Np = int(data[0][0])
            pubkey = paillier.PaillierPublicKey(n=Np)

            priv_file = f"Keys/privkey{DEFAULT_KEYSIZE}.txt"
            with open(priv_file, 'r') as fpriv:
                data = [line.split() for line in fpriv]
            p = mpz(data[0][0])
            q = mpz(data[1][0])
            privkey = paillier.PaillierPrivateKey(pubkey, p, q)

            self.pubkey = pubkey
            self.privkey = privkey
            print("[DEBUG] Loaded keys from files")

        except Exception as e:
            print(f"[DEBUG] Key files not found, generating new keys. Error: {e}")
            keypair = paillier.generate_paillier_keypair(n_length=DEFAULT_KEYSIZE)
            self.pubkey, self.privkey = keypair
            with open(f"Keys/pubkey{DEFAULT_KEYSIZE}.txt", 'w') as f:
                f.write(str(self.pubkey.n))
            with open(f"Keys/privkey{DEFAULT_KEYSIZE}.txt", 'w') as f:
                f.write(f"{self.privkey.p}\n{self.privkey.q}")
            print("[DEBUG] Generated and saved new key files")

    def load_initial_data(self, n, m, N):
        x0_file = f"Data/x0{n}_{m}_{N}.txt"
        self.x0 = np.loadtxt(x0_file)
        w0_file = f"Data/w0{n}_{m}_{N}.txt"
        w0 = np.loadtxt(w0_file, delimiter=',')
        self.hu = np.concatenate([w0[2 * i * m:(2 * i + 1) * m] for i in range(N)])
        self.lu = np.concatenate([-w0[(2 * i + 1) * m:2 * (i + 1) * m] for i in range(N)])
        print(f"[DEBUG] Loaded initial data for n={n}, m={m}, N={N}")

    def generate_random_coins(self):
        n, Kc, Kw, nc, T = self.n, self.Kc, self.Kw, self.nc, self.T
        bit_length = self.pubkey.n.bit_length()
        rnd_state = gmpy2.random_state(seed)
        coins = [gmpy2.mpz_urandomb(rnd_state, bit_length - 1) for _ in range(T * n + (T - 1) * nc * Kw + nc * Kc)]
        coins = [gmpy2.powmod(c, self.pubkey.n, self.pubkey.nsquare) for c in coins]
        self.coinsP = coins
        print(f"[DEBUG] Generated {len(coins)} random coins")

    def clip_values(self, t):
        nc = self.nc
        with np.errstate(invalid='ignore'):
            clipped = np.maximum(self.lu, np.minimum(self.hu, t))
        print("[DEBUG] Clipped values with compare function")
        return clipped


def send_encrypted_list(encrypted_list):
    time.sleep(NETWORK_DELAY)
    enc_str_list = [str(x.ciphertext()) for x in encrypted_list]
    print(f"[DEBUG] Sending encrypted data of length {len(enc_str_list)}")
    return json.dumps(enc_str_list)


def send_plain_list(data):
    time.sleep(NETWORK_DELAY)
    print(f"[DEBUG] Sending plain data of length {len(data)}")
    return json.dumps([str(x) for x in data])


def receive_data_with_size(sock):
    total_len = 0
    data_chunks = []
    size = sys.maxsize
    size_data = sock_data = bytes()
    recv_size = 4096
    while total_len < size:
        sock_data = sock.recv(recv_size)
        if not data_chunks:
            if len(sock_data) > 4:
                size = struct.unpack('>i', sock_data[:4])[0]
                recv_size = size if size <= 4096 else 4096
                data_chunks.append(sock_data[4:])
            else:
                size_data += sock_data
        else:
            data_chunks.append(sock_data)
        total_len = sum(len(chunk) for chunk in data_chunks)
    print(f"[DEBUG] Received data of size {total_len}")
    return b''.join(data_chunks)


def parse_encrypted_data(data_list, pubkey):
    enc_data = [paillier.EncryptedNumber(pubkey, int(x)) for x in data_list]
    print(f"[DEBUG] Parsed {len(enc_data)} encrypted numbers")
    return enc_data


def parse_plain_data(data_list):
    plain = [int(x) for x in data_list]
    print(f"[DEBUG] Parsed plain data: {plain}")
    return plain


def main():
    lf = DEFAULT_PRECISION
    client = Client()
    pubkey = client.pubkey
    privkey = client.privkey

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Client: Socket successfully created')
    port = 10000

    localhost = [addr for addr in (
        [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1],
        [[
            (s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close())
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        ][0][1]]
    ) if addr][0][0]

    server_addr = (localhost, port)
    print(f'Client: Starting up on {server_addr[0]} port {server_addr[1]}')
    sock.bind(server_addr)

    sock.listen(1)
    print('Client: Socket is listening')
    connection, client_address = sock.accept()

    try:
        print('Client: Connection from', client_address)
        raw_data = json.loads(receive_data_with_size(connection))
        if raw_data:
            n, m, N, Kc, Kw, T = parse_plain_data(raw_data)
            client.n, client.m, client.N = n, m, N
            client.Kc, client.Kw, client.T = Kc, Kw, T
            client.nc = m * N

            client.generate_random_coins()
            client.load_initial_data(n, m, N)

            fileA = f"Data/A{n}_{m}_{N}.txt"
            fileB = f"Data/B{n}_{m}_{N}.txt"
            A = np.loadtxt(fileA, delimiter=',')
            B = np.loadtxt(fileB, delimiter=',')

            x = [[0]*n] * (T + 1)
            u = [[0]*m] * T
            x[0] = client.x0

            start_time = time.time()
            iteration_times = [0] * T
            K = Kc
            time_client_iter = [0] * K
            time_cloud_iter = [0] * K

            for i in range(T):
                enc_x = encrypt_vals(pubkey, fixed_point_vector(x[i]), client.coinsP[-n:])
                client.coinsP = client.coinsP[:-n]

                data_to_send = send_encrypted_list(enc_x)
                connection.sendall(struct.pack('>i', len(data_to_send)) + data_to_send.encode('utf-8'))
                print(f"[DEBUG] Sent encrypted state vector x[{i}]")

                time_x = time.time() - start_time
                start_cloud = time.time()

                for k in range(K):
                    incoming = json.loads(receive_data_with_size(connection))
                    time_cloud_iter[k] = time.time() - start_cloud
                    start_client = time.time()

                    enc_t = parse_encrypted_data(incoming, pubkey)
                    t = retrieve_fixed_point_vector(decrypt_vals(privkey, enc_t), 3 * lf)

                    U = client.clip_values(t)
                    enc_U = encrypt_vals(pubkey, fixed_point_vector(U), client.coinsP[-client.nc:])
                    client.coinsP = client.coinsP[:-client.nc]

                    data_to_send = send_encrypted_list(enc_U)
                    connection.sendall(struct.pack('>i', len(data_to_send)) + data_to_send.encode('utf-8'))
                    time_client_iter[k] = time.time() - start_client
                    start_cloud = time.time()

                K = Kw
                u[i] = quant_vector(U[:m])
                print(f"Last input at step {i}: ", ["%.8f" % val for val in u[i]])
                x[i + 1] = np.dot(A, x[i]) + np.dot(B, u[i])
                print(f"Next state at step {i + 1}: ", ["%.8f" % val for val in x[i + 1]])
                iteration_times[i] = time.time() - start_time
                start_time = time.time()

            print("[DEBUG] Iteration times:", iteration_times)
            result_file = os.path.abspath(f"{DEFAULT_KEYSIZE}_{lf}_results_CS.txt")
            with open(result_file, 'a+') as f:
                f.write(f"{n}, {m}, {N}, {Kc}, {Kw}, {T}: ")
                for t in iteration_times:
                    f.write(f"total time {t:.2f} ")
                f.write("\n")
                f.write(f"avg. time FGM iteration for client: {np.mean(time_client_iter):.3f}\n")
                f.write(f"avg. time FGM iteration for cloud: {np.mean(time_cloud_iter):.3f}\n")

    finally:
        print('Client: Closing connection')
        connection.close()


if __name__ == '__main__':
    main()
