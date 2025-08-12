#!/usr/bin/env python3

import socket
import sys
import struct
import json
from gmpy2 import mpz
import paillier
import numpy as np
import time
import DGK
from pathlib import Path
import os

DEFAULT_KEYSIZE = 512
DEFAULT_MSGSIZE = 64
DEFAULT_SECURITYSIZE = 100
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE / 2)
DEFAULT_DGK = 160
NETWORK_DELAY = 0

seed = 42
try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

# ----------------------------
# Fixed-point / quantization helpers (renamed)
# ----------------------------
def quant_scalar(value, prec=DEFAULT_PRECISION):
    return int(value * (2 ** prec)) / (2 ** prec)

def quant_vector(vec, prec=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [quant_scalar(x, prec) for x in vec]
    else:
        return quant_scalar(vec, prec)

def quant_matrix(mat, prec=DEFAULT_PRECISION):
    return [quant_vector(row, prec) for row in mat]

def fixed_point_scalar(value, prec=DEFAULT_PRECISION):
    # supports negative prec (right shifts) like original
    if prec < 0:
        return gmpy2.t_div_2exp(mpz(value), -prec)
    else:
        return mpz(gmpy2.mul(value, 2 ** prec))

def fixed_point_vector(vec, prec=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [fixed_point_scalar(x, prec) for x in vec]
    else:
        return fixed_point_scalar(vec, prec)

def fixed_point_matrix(mat, prec=DEFAULT_PRECISION):
    return [fixed_point_vector(row, prec) for row in mat]

def retrieve_fixed_point(value, prec=DEFAULT_PRECISION):
    return value / (2 ** prec)

def retrieve_fixed_point_vector(vec, prec=DEFAULT_PRECISION):
    return [retrieve_fixed_point(x, prec) for x in vec]

def retrieve_fixed_point_matrix(mat, prec=DEFAULT_PRECISION):
    return [retrieve_fixed_point_vector(row, prec) for row in mat]


# ----------------------------
# Paillier & DGK helpers (renamed)
# ----------------------------
def encrypt_vals(pubkey, items, coins=None):
    """Encrypt list of integers with optional coins list (pop used)."""
    if coins is None:
        print("[DEBUG encrypt_vals] encrypting {} items without coins".format(len(items)))
        return [pubkey.encrypt(y) for y in items]
    else:
        print("[DEBUG encrypt_vals] encrypting {} items with coins".format(len(items)))
        return [pubkey.encrypt(y, coins.pop()) for y in items]

def encrypt_matrix(pubkey, mat, coins=None):
    if coins is None:
        return [[pubkey.encrypt(y) for y in row] for row in mat]
    else:
        return [[pubkey.encrypt(y, coins.pop()) for y in row] for row in mat]

def encrypt_vals_DGK(pubkey, items, coins=None):
    if coins is None:
        return [pubkey.raw_encrypt(y) for y in items]
    else:
        return [pubkey.raw_encrypt(y, coins.pop()) for y in items]

def decrypt_vals(privkey, enc_list):
    print("[DEBUG decrypt_vals] decrypting {} encrypted items".format(len(enc_list)))
    return np.array([privkey.decrypt(i) for i in enc_list])

def decrypt_vals_DGK(privkey, enc_list):
    return np.array([privkey.raw_decrypt0(i) for i in enc_list])

def sum_encrypted_vectors(x, y):
    return [x[i] + y[i] for i in range(np.size(x))]

def diff_encrypted_vectors(x, y):
    return [x[i] - y[i] for i in range(len(x))]

def mul_sc_encrypted_vectors(x, y):
   
    return [y[i] * x[i] for i in range(len(x))]

def dot_sc_encrypted_vectors(x, y):
    return sum(mul_sc_encrypted_vectors(x, y))

def dot_m_encrypted_vectors(x, A):
    return [dot_sc_encrypted_vectors(x, row) for row in A]


def encrypt_vector_DGK(pubkey, x, coins=None):
    if coins is None:
        return [pubkey.raw_encrypt(y) for y in x]
    else:
        return [pubkey.raw_encrypt(y, coins.pop()) for y in x]

def parse_encrypted_data(received_list, pubkey):
    return [paillier.EncryptedNumber(pubkey, int(x)) for x in received_list]

def send_encrypted_list(encrypted_number_list):
    time.sleep(NETWORK_DELAY)
    enc_list = [str(x.ciphertext()) for x in encrypted_number_list]
    print("[DEBUG send_encrypted_list] sending {} encrypted numbers".format(len(enc_list)))
    return json.dumps(enc_list)

def send_plain_list(data):
    time.sleep(NETWORK_DELAY)
    print("[DEBUG send_plain_list] sending plain list: {}".format(data))
    return json.dumps([str(x) for x in data])

def receive_data_with_size(the_socket):
    # data length is packed into 4 bytes
    total_len = 0
    total_data = []
    size = sys.maxsize
    size_data = sock_data = bytes([])
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
        total_len = sum([len(i) for i in total_data])
    data = b''.join(total_data)
    print("[DEBUG receive_data_with_size] received {} bytes".format(len(data)))
    return data

def parse_plain_list(data):
    return [int(x) for x in data]

def parse_comp_data(received_dict):
    return [mpz(x) for x in received_dict]

def parse_comp_matrix(received_dict):
    return [[mpz(y) for y in x] for x in received_dict]

def send_DGK_list(encrypted_number_list):
    time.sleep(NETWORK_DELAY)
    return json.dumps([str(x) for x in encrypted_number_list])

def send_DGK_matrix(encrypted_number_matrix):
    time.sleep(NETWORK_DELAY)
    return json.dumps([[str(y) for y in x] for x in encrypted_number_matrix])



class Client:
    def __init__(self, l=DEFAULT_MSGSIZE):
        filepub = "Keys/pubkey" + str(DEFAULT_KEYSIZE) + ".txt"
        with open(filepub, 'r') as fin:
            data = [line.split() for line in fin]
        Np = mpz(data[0][0])
        pubkey = paillier.PaillierPublicKey(n=Np)
        self.pubkey = pubkey

        filepriv = "Keys/privkey" + str(DEFAULT_KEYSIZE) + ".txt"
        with open(filepriv, 'r') as fin:
            data = [line.split() for line in fin]
        p = mpz(data[0][0])
        q = mpz(data[1][0])
        self.privkey = paillier.PaillierPrivateKey(pubkey, p, q)
        print("[DEBUG Client.__init__] Loaded keys and set pub/priv")

    def load_initial_data(self, n, m, N):
        fileparam = "Data/x0{}_{}_{}.txt".format(n, m, N)
        x0 = np.loadtxt(fileparam, delimiter='\n')
        self.x0 = x0
        self.enc_x0 = encrypt_vals(self.pubkey, fixed_point_vector(x0))
        filew0 = "Data/w0{}_{}_{}.txt".format(n, m, N)
        w0 = np.loadtxt(filew0, delimiter=',')
        hu = np.concatenate([w0[2 * i * m:(2 * i + 1) * m] for i in range(0, N)])
        lu = np.concatenate([-w0[(2 * i + 1) * m:2 * (i + 1) * m] for i in range(0, N)])
        self.hu = hu
        self.lu = lu
        fileA = "Data/A{}_{}_{}.txt".format(n, m, N)
        self.A = np.loadtxt(fileA, delimiter=',')
        fileB = "Data/B{}_{}_{}.txt".format(n, m, N)
        self.B = np.loadtxt(fileB, delimiter=',')
        print("[DEBUG Client.load_initial_data] loaded x0, hu, lu, A, B")

    def closed_loop(self, u):
        u = retrieve_fixed_point_vector(decrypt_vals(self.privkey, u))
        print("[DEBUG Client.closed_loop] Last input:", ["%.8f" % i for i in u])
        with np.errstate(invalid='ignore'):
            self.x0 = np.dot(self.A, self.x0) + np.dot(self.B, u)
        print("[DEBUG Client.closed_loop] Next state:", ["%.8f" % i for i in self.x0])
        self.enc_x0 = encrypt_vals(self.pubkey, fixed_point_vector(self.x0))

class Server1:
    def __init__(self, n, m, N, T, l=DEFAULT_MSGSIZE, sigma=DEFAULT_SECURITYSIZE):
        self.l = l
        self.sigma = sigma

        filepub = "Keys/pubkey" + str(DEFAULT_KEYSIZE) + ".txt"
        with open(filepub, 'r') as fin:
            data = [line.split() for line in fin]
        Np = mpz(data[0][0])
        self.Np = Np
        pubkey = paillier.PaillierPublicKey(n=Np)
        self.pubkey = pubkey
        self.N_len = Np.bit_length()

        # load system matrices and parameters
        fileH = "Data/H{}_{}_{}.txt".format(n, m, N)
        fileF = "Data/F{}_{}_{}.txt".format(n, m, N)
        fileG0 = "Data/G0{}_{}_{}.txt".format(n, m, N)
        fileK = "Data/K{}_{}_{}.txt".format(n, m, N)

        H = np.loadtxt(fileH, delimiter=',')
        F = np.loadtxt(fileF, delimiter=',')
        G0 = np.loadtxt(fileG0, delimiter=',')
        K = np.loadtxt(fileK, delimiter=',')
        Kc = K[0]; Kw = K[1]
        self.Kc = int(Kc); self.Kw = int(Kw); self.T = T
        self.m = m
        nc = m * N
        self.nc = nc

        Hq = quant_matrix(H)
        eigs = np.linalg.eigvals(Hq)
        L = np.real(max(eigs))
        mu = np.real(min(eigs))
        cond = quant_scalar(L / mu)
        eta = quant_scalar((np.sqrt(cond) - 1) / (np.sqrt(cond) + 1))
        Hf = quant_matrix([[h / quant_scalar(L) for h in hv] for hv in Hq])
        Ft = F.transpose()
        Ff = quant_matrix([[quant_scalar(h) / quant_scalar(L) for h in hv] for hv in Ft])
        self.eta = eta
        self.Hf = Hf
        mFf = np.negative(Ff)
        # mFft scaled to 2*DEFAULT_PRECISION
        self.mFft = fixed_point_matrix(mFf, 2 * DEFAULT_PRECISION)

        coeff_z = np.eye(nc) - Hf
        self.coeff_z = fixed_point_matrix(coeff_z)
        print("[DEBUG Server1.__init__] Server1 initialized: n={}, m={}, N={}, nc={}".format(n, m, N, nc))

    def generate_random_coins(self, DGK_pubkey):
        """(previously gen_rands) prepare all randomness / obfuscations"""
        print("[DEBUG Server1.generate_random_coins] start")
        self.DGK_pubkey = DGK_pubkey
        T = self.T
        nc = self.nc
        m = self.m
        l = self.l
        lf = DEFAULT_PRECISION
        sigma = self.sigma
        Kc = self.Kc
        Kw = self.Kw
        random_state = gmpy2.random_state(seed)

        filePath = Path('Randomness/' + str(l + sigma) + '.txt')
        if filePath.is_file():
            print("[DEBUG] Loading obfuscation from file")
            with open(filePath) as f:
                rn1 = [[[int(next(f)), int(next(f))] for _ in range(0, 2 * nc)] for _ in range(0, Kc + (T - 1) * Kw)]
                rn2 = [[int(next(f)) for _ in range(0, nc)] for _ in range(0, 2 * Kc + 2 * (T - 1) * Kw)]
        else:
            print("[DEBUG] Generating obfuscation randomly")
            rn1 = [[[gmpy2.mpz_urandomb(random_state, l + sigma), gmpy2.mpz_urandomb(random_state, l + sigma)]
                    for _ in range(0, 2 * nc)] for _ in range(0, Kc + (T - 1) * Kw)]
            rn2 = [[gmpy2.mpz_urandomb(random_state, l + sigma) for _ in range(0, nc)]
                   for _ in range(0, 2 * Kc + 2 * (T - 1) * Kw)]
        self.obfuscations = rn1
        self.rn = rn2

        filePath = Path('Randomness/' + str(self.N_len) + '.txt')
        if filePath.is_file():
            with open(filePath) as f:
                coinsP = [int(next(f)) for _ in range(0, 4 * (T - 1) * nc * Kw + 4 * nc * Kc)]
        else:
            coinsP = [gmpy2.mpz_urandomb(random_state, self.N_len - 1) for _ in range(0, 4 * (T - 1) * nc * Kw + 4 * nc * Kc)]
        coinsP = [gmpy2.powmod(x, self.Np, self.pubkey.nsquare) for x in coinsP]

        filePath = Path('Randomness/' + str(2 * DEFAULT_DGK) + '.txt')
        if filePath.is_file():
            with open(filePath) as f:
                coinsDGK = [int(next(f)) for _ in range(0, 3 * (l + 1) * nc * Kc + 3 * (l + 1) * nc * Kw * (T - 1))]
        else:
            coinsDGK = [gmpy2.mpz_urandomb(random_state, 2 * DEFAULT_DGK)
                        for _ in range(0, 3 * (l + 1) * nc * Kc + 3 * (l + 1) * nc * Kw * (T - 1))]
        coinsDGK = [gmpy2.powmod(self.DGK_pubkey.h, x, self.DGK_pubkey.n) for x in coinsDGK]
        self.coinsDGK = coinsDGK

        filePath = Path('Randomness/' + str(l + 2 * lf + sigma) + '.txt')
        if filePath.is_file():
            with open(filePath) as f:
                rn = [int(next(f)) for _ in range(0, nc * Kc + nc * Kw * (T - 1))]
        else:
            rn = [gmpy2.mpz_urandomb(random_state, l + 2 * lf + sigma) for _ in range(0, nc * Kc + nc * Kw * (T - 1))]

        self.fixedNoise = encrypt_vals(self.pubkey, rn)
        er = [-fixed_point_scalar(x, -2 * lf) for x in rn]
        er = encrypt_vals(self.pubkey, er)
        self.er = er
        self.coinsP = coinsP
        print("[DEBUG Server1.generate_random_coins] done: len(coinsP)={}, len(coinsDGK)={}, fixedNoise len={}".format(
            len(self.coinsP), len(self.coinsDGK), len(self.fixedNoise)))

    def compute_coeff(self, x0):
        print("[DEBUG Server1.compute_coeff] computing coeff_0")
        coeff_0 = np.dot(self.mFft, x0)
        self.coeff_0 = coeff_0

    def t_iterate(self, z):
        print("[DEBUG Server1.t_iterate] computing t from z")
        return sum_encrypted_vectors(np.dot(self.coeff_z, z), self.coeff_0)

    def z_iterate(self, new_U, U):
        print("[DEBUG Server1.z_iterate] computing z from new_U and U")
        new_z = [fixed_point_scalar(1 + self.eta) * v for v in new_U]
        z = [fixed_point_scalar(-self.eta) * v for v in U]
        return sum_encrypted_vectors(new_z, z)

    def temporary_prec_t(self):
        nc = self.nc
        pubkey = self.pubkey
        r = [self.fixedNoise.pop() for _ in range(0, nc)]
        temp_t = sum_encrypted_vectors(self.t, r)
        print("[DEBUG Server1.temporary_prec_t] prepared temp_t (with fixed noise)")
        return temp_t

    def randomize(self, limit):
        nc = self.nc
        a = [0] * nc
        b = [0] * nc
        for i in range(0, nc):
            a[i], b[i] = np.random.permutation([limit[i] + self.pubkey.encrypt(0), self.t[i]])
        self.a = a
        self.b = b
        print("[DEBUG Server1.randomize] randomized a and b")
        return self.a, self.b

    def init_comparison_s1(self, limit):
        nc = self.nc
        l = self.l
        pubkey = self.pubkey
        r = self.r
        a, b = self.randomize(limit)
        z = diff_encrypted_vectors(b, a)
        z = sum_encrypted_vectors(z, encrypt_vals(pubkey, r, self.coinsP[-nc:]))
        z = sum_encrypted_vectors(z, encrypt_vals(pubkey, [2 ** l] * nc, self.coinsP[-2 * nc:-nc]))
        self.coinsP = self.coinsP[:-2 * nc]
        alpha = [gmpy2.t_mod_2exp(x, l) for x in r]
        alpha = [x.digits(2) for x in alpha]
        for i in range(0, nc):
            if len(alpha[i]) < l:
                alpha[i] = "".join(['0' * (l - len(alpha[i])), alpha[i]])
        self.alpha = alpha
        print("[DEBUG Server1.init_comparison_s1] prepared z for DGK comparison")
        return z

    def obfuscate(self):
        nc = self.nc
        self.a2 = [0] * nc
        self.b2 = [0] * nc
        for i in range(0, nc):
            r = self.obfuscation[i]
            self.a2[i] = self.a[i] + self.pubkey.encrypt(r[0])
            self.b2[i] = self.b[i] + self.pubkey.encrypt(r[1])
        print("[DEBUG Server1.obfuscate] created a2 and b2 vectors")
        return self.a2, self.b2

    def update_max(self, v):
        new_U = [0] * self.nc
        for i in range(0, self.nc):
            r = self.obfuscation[i]
            new_U[i] = v[i] + (self.t_comp[i] - 1) * r[0] + self.t_comp[i] * (-r[1])
        print("[DEBUG Server1.update_max] updated max")
        return new_U

    def update_min(self, v):
        t_vec = [0] * self.nc
        for i in range(0, self.nc):
            r = self.obfuscation[i]
            t_vec[i] = v[i] + (self.t_comp[i] - 1) * r[1] + self.t_comp[i] * (-r[0])
        print("[DEBUG Server1.update_min] updated min")
        return t_vec

    def DGK_s1(self, b):
        l = self.l
        nc = self.nc
        self.delta_A = [0] * nc
        c_all = [[0] * l] * nc
        for k in range(0, nc):
            beta = b[k]
            alpha = self.alpha[k]
            DGK_pubkey = self.DGK_pubkey
            delta_A = np.random.randint(0, 2)
            self.delta_A[k] = delta_A
            prod = [0] * l
            c = [DGK_pubkey.raw_encrypt(0)] * l
            for i in range(0, l):
                if int(alpha[i]) == 0:
                    prod[i] = beta[i]
                else:
                    prod[i] = DGK.diff_encrypted(DGK_pubkey.raw_encrypt(1, self.coinsDGK.pop()), beta[i], DGK_pubkey)
                if int(delta_A) == int(alpha[i]):
                    if i == 0:
                        c[i] = DGK_pubkey.raw_encrypt(0, self.coinsDGK.pop())
                    else:
                        for iter_i in range(0, i):
                            c[i] = DGK.add_encrypted(c[i], prod[iter_i], DGK_pubkey)
                    if int(delta_A) == 0:
                        diff = DGK.diff_encrypted(DGK_pubkey.raw_encrypt(1, self.coinsDGK.pop()), beta[i], DGK_pubkey)
                        c[i] = DGK.add_encrypted(c[i], diff, DGK_pubkey)
                    else:
                        c[i] = DGK.add_encrypted(c[i], beta[i], DGK_pubkey)
            for i in range(0, l):
                if int(delta_A) == int(alpha[i]):
                    r = gmpy2.mpz_urandomb(gmpy2.random_state(), self.sigma + self.sigma)
                    c[i] = DGK.mul_sc_encrypted(c[i], r, DGK_pubkey)
                else:
                    c[i] = DGK_pubkey.raw_encrypt(gmpy2.mpz_urandomb(gmpy2.random_state(), self.sigma + self.sigma),
                                                  self.coinsDGK.pop())
            c_all[k] = np.random.permutation(c)
        print("[DEBUG Server1.DGK_s1] produced DGK responses")
        return c_all

    def compute_tDGK(self, delta_B, zdivl):
        t_comp = [0] * self.nc
        for i in range(0, self.nc):
            if self.delta_A[i] == 1:
                t_comp[i] = delta_B[i]
            else:
                t_comp[i] = self.pubkey.encrypt(1) - delta_B[i]
            t_comp[i] = zdivl[i] - self.pubkey.encrypt(mpz(gmpy2.t_div_2exp(self.r[i], self.l))) - t_comp[i]
        self.t_comp = t_comp
        print("[DEBUG Server1.compute_tDGK] computed t_comp")
        return t_comp


def key(serialised):
    received_dict = json.loads(serialised)
    pk = received_dict['public_key_DGK']
    n = mpz(pk['n']); g = mpz(pk['g']); h = mpz(pk['h']); u = mpz(pk['u'])
    DGK_pubkey = DGK.DGKpubkey(n=n, g=g, h=h, u=u)
    print("[DEBUG] Parsed DGK public key")
    return DGK_pubkey


def main():
    lf = DEFAULT_PRECISION
    n = 5; m = 5; N = 7; T = 1
    print("[DEBUG main] Starting Server1 main")
    s1 = Server1(n, m, N, T)
    s1.Kc = 50; s1.Kw = 20
    Kc = s1.Kc; Kw = s1.Kw
    nc = s1.nc
    pubkey = s1.pubkey
    U = [0] * nc

    client = Client()
    client.n = n; client.m = m; client.N = N; client.Kc = Kc; client.Kw = Kw; client.T = T
    client.nc = nc
    client.load_initial_data(n, m, N)

    s1.hu = encrypt_vals(client.pubkey, fixed_point_vector(client.hu))
    s1.lu = encrypt_vals(client.pubkey, fixed_point_vector(client.lu))
    print("[DEBUG main] Encrypted hu/lu set for Server1")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 10000

    localhost = [l for l in (
        [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1],
        [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]
    ) if l][0][0]
    server_address = (localhost, port)
    print('Server1: Connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    print("[DEBUG main] connected to Server2 at {}".format(server_address))

    cont = 1
    try:
        while cont:
            print("[DEBUG main] sending params n,m,N,Kc,Kw,T")
            data = send_plain_list([n, m, N, Kc, Kw, T])
            sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))

            U = encrypt_vals(pubkey, fixed_point_vector(U))
            z = [uz * (2 ** lf) for uz in U]
            K = Kc

            # Get DGK_pubkey
            data_raw = receive_data_with_size(sock)
            DGK_pubkey = key(data_raw)
            s1.generate_random_coins(DGK_pubkey)

            sec = [0] * T
            time_s1 = [0] * K
            time_s2 = [0] * K

            start = time.time()
            for i in range(0, T):
                x0 = client.enc_x0
                s1.compute_coeff(x0)
                for k in range(0, K):
                    start_s1 = time.time()
                    s1.t = s1.t_iterate(z)
                    s1.obfuscation = s1.obfuscations[k]
                    s1.r = s1.rn[k]
                    temp_t = s1.temporary_prec_t()
                    data_out = send_encrypted_list(temp_t)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data_out)) + data_out.encode('utf-8'))
                    print(f"[DEBUG main] sent temp_t at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    temp_tr = parse_encrypted_data(data, pubkey)
                    s1.t = sum_encrypted_vectors(temp_tr, [s1.er.pop() for _ in range(0, nc)])

                    # Projection on hu
                    z_DGK = s1.init_comparison_s1(s1.hu)
                    data_out = send_encrypted_list(z_DGK)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data_out)) + data_out.encode('utf-8'))
                    print(f"[DEBUG main] sent z_DGK for hu at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    b = parse_comp_matrix(data)
                    c = s1.DGK_s1(b)
                    serialized_c = send_DGK_matrix(c)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(serialized_c)) + serialized_c.encode('utf-8'))
                    print(f"[DEBUG main] sent DGK responses c at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    merged = parse_encrypted_data(data, pubkey)
                    delta_B = merged[:nc]; zdivl = merged[nc:]
                    t_comp = s1.compute_tDGK(delta_B, zdivl)

                    a2, b2 = s1.obfuscate()
                    data_out = send_encrypted_list(t_comp + a2 + b2)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data_out)) + data_out.encode('utf-8'))
                    print(f"[DEBUG main] sent t_comp + a2 + b2 at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    v = parse_encrypted_data(data, pubkey)
                    s1.t = s1.update_min(v)

                    # Projection on lu
                    z_DGK = s1.init_comparison_s1(s1.lu)
                    data_out = send_encrypted_list(z_DGK)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data_out)) + data_out.encode('utf-8'))
                    print(f"[DEBUG main] sent z_DGK for lu at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    b = parse_comp_matrix(data)
                    c = s1.DGK_s1(b)
                    serialized_c = send_DGK_matrix(c)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(serialized_c)) + serialized_c.encode('utf-8'))
                    print(f"[DEBUG main] sent DGK responses c (lu) at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    merged = parse_encrypted_data(data, pubkey)
                    delta_B = merged[:nc]; zdivl = merged[nc:]
                    t_comp = s1.compute_tDGK(delta_B, zdivl)

                    a2, b2 = s1.obfuscate()
                    data_out = send_encrypted_list(t_comp + a2 + b2)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data_out)) + data_out.encode('utf-8'))
                    print(f"[DEBUG main] sent t_comp + a2 + b2 (lu) at k={k}")

                    start_s2 = time.time()
                    data = json.loads(receive_data_with_size(sock))
                    time_s2[k] += time.time() - start_s2

                    start_s1 = time.time()
                    v = parse_encrypted_data(data, pubkey)
                    new_U = s1.update_max(v)

                    # update iterate
                    z = s1.z_iterate(new_U, U)
                    U = new_U
                    time_s1[k] += time.time() - start_s1
                u = U[:m]
                client.closed_loop(u)
                U = list(U[m:]) + list([pubkey.encrypt(0)] * m)
                z = [el * 2 ** lf for el in U]
                K = Kw
                sec[i] = time.time() - start
                start = time.time()

            print("[DEBUG main] total time per step:", sec)
            with open(os.path.abspath(str(DEFAULT_KEYSIZE) + '_' + str(DEFAULT_PRECISION) + '_results_SS' + '.txt'), 'a+') as f:
                f.write("%d, %d, %d, %d, %d, %d: " % (n, m, N, Kc, Kw, T))
                for item in sec:
                    f.write("total time %.2f " % item)
                f.write("\n")
                f.write("avg. time FGM iteration for S1: %.3f\n" % np.mean(time_s1))
                f.write("avg. time FGM iteration for S2: %.3f\n" % np.mean(time_s2))

            cont = 0

    finally:
        print('Server1: Closing sock')
        sock.close()


if __name__ == '__main__':
    main()
