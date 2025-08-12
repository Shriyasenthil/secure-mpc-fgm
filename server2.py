#!/usr/bin/env python3

import socket
import sys, struct
import json
from gmpy2 import mpz
import paillier
from pathlib import Path
import numpy as np
import time
import DGK
import genDGK
import os

DEFAULT_KEYSIZE = 512
DEFAULT_MSGSIZE = 64
DEFAULT_SECURITYSIZE = 100
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE / 2)
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


def encrypt_vals(pubkey, x, coins=None):
    if coins is None:
        print("[DEBUG] encrypt_vals: Encrypting without coins")
        return [pubkey.encrypt(y) for y in x]
    else:
        print("[DEBUG] encrypt_vals: Encrypting with coins")
        return [pubkey.encrypt(y, coins.pop()) for y in x]


def encrypt_matrix(pubkey, x, coins=None):
    if coins is None:
        print("[DEBUG] encrypt_matrix: Encrypting matrix without coins")
        return [[pubkey.encrypt(y) for y in z] for z in x]
    else:
        print("[DEBUG] encrypt_matrix: Encrypting matrix with coins")
        return [[pubkey.encrypt(y, coins.pop()) for y in z] for z in x]


def decrypt_vals(privkey, x):
    print("[DEBUG] decrypt_vals: Decrypting vector")
    return np.array([privkey.decrypt(i) for i in x])


def sum_encrypted_vectors(x, y):
    return [x[i] + y[i] for i in range(np.size(x))]


def diff_encrypted_vectors(x, y):
    return [x[i] - y[i] for i in range(len(x))]


def mul_sc_encrypted_vectors(x, y):  # x encrypted, y plaintext
    return [y[i] * x[i] for i in range(len(x))]


def dot_sc_encrypted_vectors(x, y):  # x encrypted, y plaintext
    return sum(mul_sc_encrypted_vectors(x, y))


def dot_m_encrypted_vectors(x, A):
    return [dot_sc_encrypted_vectors(x, vec) for vec in A]


def encrypt_vector_DGK(pubkey, x, coins=None):
    if coins is None:
        print("[DEBUG] encrypt_vector_DGK: Encrypting DGK vector without coins")
        return [pubkey.raw_encrypt(y) for y in x]
    else:
        print("[DEBUG] encrypt_vector_DGK: Encrypting DGK vector with coins")
        return [pubkey.raw_encrypt(y, coins.pop()) for y in x]


def decrypt_vector_DGK(privkey, x):
    print("[DEBUG] decrypt_vector_DGK: Decrypting DGK vector")
    return np.array([privkey.raw_decrypt0(i) for i in x])


def quant_scalar(scalar, prec=DEFAULT_PRECISION):
    return int(scalar * (2 ** prec)) / (2 ** prec)


def quant_vector(vec, prec=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [quant_scalar(x, prec) for x in vec]
    else:
        return quant_scalar(vec, prec)


def quant_matrix(mat, prec=DEFAULT_PRECISION):
    return [quant_vector(x, prec) for x in mat]


def fixed_point_scalar(scalar, prec=DEFAULT_PRECISION):
    if prec < 0:
        return gmpy2.t_div_2exp(mpz(scalar), -prec)
    else:
        return mpz(gmpy2.mul(scalar, 2 ** prec))


def fixed_point_vector(vec, prec=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [fixed_point_scalar(x, prec) for x in vec]
    else:
        return fixed_point_scalar(vec, prec)


def fixed_point_matrix(mat, prec=DEFAULT_PRECISION):
    return [fixed_point_vector(x, prec) for x in mat]


def retrieve_fixed_point(scalar, prec=DEFAULT_PRECISION):
    return scalar / (2 ** prec)


def retrieve_fixed_point_vector(vec, prec=DEFAULT_PRECISION):
    return [retrieve_fixed_point(x, prec) for x in vec]


def retrieve_fixed_point_matrix(mat, prec=DEFAULT_PRECISION):
    return [retrieve_fixed_point_vector(x, prec) for x in mat]


class Server2:
    def __init__(self, l=DEFAULT_MSGSIZE, t_DGK=DEFAULT_DGK, sigma=DEFAULT_SECURITYSIZE):
        print("[DEBUG] Server2 init: Loading or generating keys")
        try:
            pub_file = f"Keys/pubkey{DEFAULT_KEYSIZE}.txt"
            with open(pub_file, 'r') as fin:
                data = [line.split() for line in fin]
            Np = int(data[0][0])
            pubkey = paillier.PaillierPublicKey(n=Np)

            priv_file = f"Keys/privkey{DEFAULT_KEYSIZE}.txt"
            with open(priv_file, 'r') as fin:
                data = [line.split() for line in fin]
            p = mpz(data[0][0])
            q = mpz(data[1][0])
            privkey = paillier.PaillierPrivateKey(pubkey, p, q)

            self.pubkey = pubkey
            self.privkey = privkey
            print("[DEBUG] Server2 init: Keys loaded successfully")

        except Exception as e:
            print("[DEBUG] Server2 init: Key files not found, generating keys", e)
            keypair = paillier.generate_paillier_keypair(n_length=DEFAULT_KEYSIZE)
            self.pubkey, self.privkey = keypair
            Np = self.pubkey.n
            with open(f'Keys/pubkey{DEFAULT_KEYSIZE}.txt', 'w') as f:
                f.write("%d" % (self.pubkey.n))
            with open(f'Keys/privkey{DEFAULT_KEYSIZE}.txt', 'w') as f:
                f.write("%d\n%d" % (self.privkey.p, self.privkey.q))

        self.N_len = Np.bit_length()
        self.l = l
        self.t_DGK = t_DGK
        self.sigma = sigma
        self.generate_DGK()

    def params(self, n, m, N, Kc, Kw, T):
        print(f"[DEBUG] Server2 params: n={n}, m={m}, N={N}, Kc={Kc}, Kw={Kw}, T={T}")
        self.Kc = Kc
        self.Kw = Kw
        self.nc = m * N

        random_state = gmpy2.random_state(seed)
        t2 = 2 * self.t_DGK

        filePathP = Path(f'Randomness/{self.N_len}.txt')
        if filePathP.is_file():
            print("[DEBUG] Loading Paillier coins from file")
            with open(filePathP) as file:
                coinsP = [int(next(file)) for _ in range(7 * (T - 1) * self.nc * Kw + 7 * self.nc * Kc)]
        else:
            print("[DEBUG] Generating Paillier coins randomly")
            coinsP = [gmpy2.mpz_urandomb(random_state, self.N_len - 1)
                      for _ in range(7 * (T - 1) * self.nc * Kw + 7 * self.nc * Kc)]
        self.coinsP = [gmpy2.powmod(x, self.pubkey.n, self.pubkey.nsquare) for x in coinsP]

        filePathDGK = Path(f'Randomness/{t2}.txt')
        if filePathDGK.is_file():
            print("[DEBUG] Loading DGK coins from file")
            with open(filePathDGK) as file:
                coinsDGK = [int(next(file)) for _ in range(2 * (self.l + 1) * self.nc * Kc + 2 * (self.l + 1) * self.nc * Kw * (T - 1))]
        else:
            print("[DEBUG] Generating DGK coins randomly")
            coinsDGK = [gmpy2.mpz_urandomb(random_state, t2)
                        for _ in range(2 * (self.l + 1) * self.nc * Kc + 2 * (self.l + 1) * self.nc * Kw * (T - 1))]
        self.coinsDGK = [gmpy2.powmod(self.DGK_pubkey.h, x, self.DGK_pubkey.n) for x in coinsDGK]

    def init_comparison_s2(self, msg):
        print("[DEBUG] Server2 init_comparison_s2: Decrypting and bit extracting")
        z = decrypt_vals(self.privkey, msg)
        self.z = [mpz(x) for x in z]
        beta = [gmpy2.t_mod_2exp(x, self.l) for x in self.z]
        beta = [x.digits(2) for x in beta]

        for i in range(self.nc):
            if len(beta[i]) < self.l:
                beta[i] = '0' * (self.l - len(beta[i])) + beta[i]

        self.beta = beta

    def generate_DGK(self):
        print("[DEBUG] Server2 generate_DGK: Loading or generating DGK keys")
        try:
            keyfile = f'Keys/DGK_keys{KEYSIZE_DGK}_{MSGSIZE_DGK}.txt'
            p, q, u, vp, vq, fp, fq, g, h = DGK.loadkey(keyfile)
        except Exception as e:
            print("[DEBUG] DGK keys not found, generating new ones", e)
            p, q, u, vp, vq, fp, fq, g, h = genDGK.keysDGK(KEYSIZE_DGK, MSGSIZE_DGK, self.t_DGK)
            with open(os.path.abspath(keyfile), 'w') as f:
                f.write(f"{p}\n{q}\n{u}\n{vp}\n{vq}\n{fp}\n{fq}\n{g}\n{h}")

        n = p * q
        self.DGK_pubkey = DGK.DGKpubkey(n, g, h, u)
        self.DGK_privkey = DGK.DGKprivkey(p, q, vp, self.DGK_pubkey)

    def DGK_s2(self, c_all):
        print("[DEBUG] Server2 DGK_s2: Performing DGK-based comparison")
        for i in range(self.nc):
            c = c_all[i]
            self.delta_B[i] = 0
            for j in range(self.l):
                if int(self.DGK_privkey.raw_decrypt0(c[j])) == 0:
                    self.delta_B[i] = 1
                    break
        db = encrypt_vals(self.pubkey, self.delta_B, self.coinsP[-self.nc:])
        z = encrypt_vals(self.pubkey,
                         [mpz(gmpy2.t_div_2exp(self.z[i], self.l)) for i in range(self.nc)],
                         self.coinsP[-2 * self.nc:-self.nc])
        self.coinsP = self.coinsP[:-2 * self.nc]
        return db, z

    def choose_max(self, a, b):
        print("[DEBUG] Server2 choose_max: Selecting max values")
        v = [0] * self.nc
        for i in range(self.nc):
            if int(self.t_comp[i]) == 0:
                v[i] = a[i] + self.pubkey.encrypt(0, self.coinsP.pop())
            else:
                v[i] = b[i] + self.pubkey.encrypt(0, self.coinsP.pop())
        return v

    def choose_min(self, a, b):
        print("[DEBUG] Server2 choose_min: Selecting min values")
        v = [0] * self.nc
        for i in range(self.nc):
            if int(self.t_comp[i]) == 1:
                v[i] = a[i] + self.pubkey.encrypt(0, self.coinsP.pop())
            else:
                v[i] = b[i] + self.pubkey.encrypt(0, self.coinsP.pop())
        return v


def keys(DGK_pubkey):
    pubkeys = {
        'public_key_DGK': {
            'n': int(DGK_pubkey.n),
            'g': int(DGK_pubkey.g),
            'h': int(DGK_pubkey.h),
            'u': int(DGK_pubkey.u)
        }
    }
    return json.dumps(pubkeys)


def parse_encrypted_data(received_dict, pubkey):
    return [paillier.EncryptedNumber(pubkey, int(x)) for x in received_dict]


def parse_plain_data(data):
    return [int(x) for x in data]


def receive_data_with_size(the_socket):
    total_len = 0
    total_data = []
    size = sys.maxsize
    size_data = b''
    recv_size = 4096
    while total_len < size:
        sock_data = the_socket.recv(recv_size)
        if not total_data:
            if len(sock_data) > 4:
                size = struct.unpack('>i', sock_data[:4])[0]
                recv_size = size
                if recv_size > 262144:
                    recv_size = 262144
                total_data.append(sock_data[4:])
            else:
                size_data += sock_data
        else:
            total_data.append(sock_data)
        total_len = sum(len(i) for i in total_data)
    return b''.join(total_data)


def send_encrypted_list(encrypted_number_list):
    time.sleep(NETWORK_DELAY)
    encrypted = [str(x.ciphertext()) for x in encrypted_number_list]
    return json.dumps(encrypted)


def send_DGK_list(encrypted_number_list):
    time.sleep(NETWORK_DELAY)
    encrypted = [str(x) for x in encrypted_number_list]
    return json.dumps(encrypted)


def send_DGK_matrix(encrypted_number_list):
    time.sleep(NETWORK_DELAY)
    encrypted = [[str(y) for y in x] for x in encrypted_number_list]
    return json.dumps(encrypted)


def get_DGK_data(received_dict):
    return [mpz(x) for x in received_dict]


def get_DGK_matrix(received_dict):
    return [[mpz(y) for y in x] for x in received_dict]


def main():
    print("[INFO] Server2: Initializing server")
    lf = DEFAULT_PRECISION
    s2 = Server2()
    l = s2.l
    pubkey = s2.pubkey
    privkey = s2.privkey
    DGK_pubkey = s2.DGK_pubkey
    serialized_pubkey = keys(DGK_pubkey)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('[INFO] Server2: Socket successfully created')

    port = 10000
    localhost = [l for l in (
        [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1],
        [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]
    ) if l][0][0]

    server_address = (localhost, port)
    print(f'[INFO] Server2: Starting up on {server_address[0]} port {server_address[1]}')
    sock.bind(server_address)
    sock.listen(1)
    print('[INFO] Server2: Socket is listening')

    connection, client_address = sock.accept()
    try:
        print('[INFO] Server2: Connection from', client_address)
        raw_data = receive_data_with_size(connection)
        data = json.loads(raw_data)
        if data:
            n, m, N, Kc, Kw, T = parse_plain_data(data)
            s2.params(n, m, N, Kc, Kw, T)
            nc = m * N
            K = Kc

            # Send DGK public key
            connection.sendall(struct.pack('>i', len(serialized_pubkey)) + serialized_pubkey.encode('utf-8'))

            for t_iter in range(T):
                for k_iter in range(K):
                    print(f"[DEBUG] Processing iteration t={t_iter}, k={k_iter}")
                    # Receive temp_t + r encrypted vector
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    temp_tr = parse_encrypted_data(data, pubkey)
                    temp_tr = decrypt_vals(privkey, temp_tr)
                    temp_tr = fixed_point_vector(temp_tr, -2 * lf)
                    temp_tr = encrypt_vals(s2.pubkey, temp_tr, s2.coinsP[-nc:])
                    s2.coinsP = s2.coinsP[:-nc]
                    serialized_data = send_encrypted_list(temp_tr)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    # Projection on hu
                    s2.delta_B = [0] * nc

                    # Receive z_DGK
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    z_DGK = parse_encrypted_data(data, pubkey)
                    s2.init_comparison_s2(z_DGK)

                    s2.coinsDGK = s2.coinsDGK[:-nc]
                    b = [
                        encrypt_vector_DGK(DGK_pubkey, [int(s2.beta[i][j]) for j in range(l)], s2.coinsDGK[-(i + 1) * l:-i * l] or s2.coinsDGK[-l:])
                        for i in range(nc)
                    ]
                    s2.coinsDGK = s2.coinsDGK[:-l * nc]

                    serialized_data = send_DGK_matrix(b)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    # Receive c
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    c = get_DGK_matrix(data)
                    delta_B, zdivl = s2.DGK_s2(c)
                    serialized_data = send_encrypted_list(delta_B + zdivl)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    # Receive t,a2,bs
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    merged = parse_encrypted_data(data, pubkey)
                    t_comp = merged[:nc]
                    a2 = merged[nc:2 * nc]
                    b2 = merged[2 * nc:]
                    s2.t_comp = decrypt_vals(s2.privkey, t_comp)
                    v = s2.choose_min(a2, b2)
                    serialized_data = send_encrypted_list(v)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    # Projection on lu
                    s2.delta_B = [0] * nc

                    # Receive z_DGK
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    z_DGK = parse_encrypted_data(data, pubkey)
                    s2.init_comparison_s2(z_DGK)
                    b = [
                        encrypt_vector_DGK(DGK_pubkey, [int(s2.beta[i][j]) for j in range(l)], s2.coinsDGK[-(i + 1) * l:-i * l] or s2.coinsDGK[-l:])
                        for i in range(nc)
                    ]
                    s2.coinsDGK = s2.coinsDGK[:-l * nc]

                    serialized_data = send_DGK_matrix(b)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    # Receive c
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    c = get_DGK_matrix(data)
                    delta_B, zdivl = s2.DGK_s2(c)
                    serialized_data = send_encrypted_list(delta_B + zdivl)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    # Receive t,a2,bs
                    raw_data = receive_data_with_size(connection)
                    data = json.loads(raw_data)
                    merged = parse_encrypted_data(data, pubkey)
                    t_comp = merged[:nc]
                    a2 = merged[nc:2 * nc]
                    b2 = merged[2 * nc:]
                    s2.t_comp = decrypt_vals(s2.privkey, t_comp)
                    v = s2.choose_max(a2, b2)
                    serialized_data = send_encrypted_list(v)
                    connection.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))

                    K = Kw

    finally:
        print('[INFO] Server2: Closing connection')
        connection.close()


if __name__ == '__main__':
    main()
