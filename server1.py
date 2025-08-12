#!/usr/bin/env python3

import socket
import sys, struct
import json
from gmpy2 import mpz
import paillier
from paillier import PaillierPublicKey, PaillierPrivateKey
import numpy as np
import time
import DGK
import util_fpv
from util_fpv import clamp_scalar
from pathlib import Path
import os
import labhe
import random

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


def encrypt_vector(pubkey, x, coins=None):
    if (coins == None):
        return [pubkey.encrypt(y) for y in x]
    else:
        return [pubkey.encrypt(y, coins.pop()) for y in x]


def encrypt_matrix(pubkey, x, coins=None):
    if (coins == None):
        return [[pubkey.encrypt(y) for y in z] for z in x]
    else:
        return [[pubkey.encrypt(y, coins.pop()) for y in z] for z in x]


def decrypt_vector(privkey, x):
    return np.array([privkey.decrypt(i) for i in x])


def sum_encrypted_vectors(x, y):
    return [x[i] + y[i] for i in range(np.size(x))]


def diff_encrypted_vectors(x, y):
    return [x[i] - y[i] for i in range(len(x))]


def mul_sc_encrypted_vectors(x, y):
    return [y[i] * x[i] for i in range(len(x))]


def dot_sc_encrypted_vectors(x, y):
    return sum(mul_sc_encrypted_vectors(x, y))


def dot_m_encrypted_vectors(x, A):
    return [dot_sc_encrypted_vectors(x, vec) for vec in A]


def encrypt_vector_DGK(pubkey, x, coins=None):
    if (coins == None):
        return [pubkey.raw_encrypt(y) for y in x]
    else:
        return [pubkey.raw_encrypt(y, coins.pop()) for y in x]


def decrypt_vector_DGK(privkey, x):
    return np.array([privkey.raw_decrypt0(i) for i in x])


def Q_s(scalar, prec=DEFAULT_PRECISION):
    return int(scalar * (2 ** prec)) / (2 ** prec)


def Q_vector(vec, prec=DEFAULT_PRECISION):
    if np.size(vec) > 1:
        return [Q_s(x, prec) for x in vec]
    else:
        return Q_s(vec, prec)


def Q_matrix(mat, prec=DEFAULT_PRECISION):
    return [Q_vector(x, prec) for x in mat]


def fp(val, lf=32, max_val=None):
    scale = 2 ** lf
    fixed = int(round(val * scale))
    if max_val is not None:
        return clamp_scalar(fixed, max_val)
    return fixed


def fp_vector(vec, lf=32, max_val=None):
    scale = 2 ** lf
    return [clamp_scalar(int(round(v * scale)), max_val) if max_val is not None else int(round(v * scale)) for v in vec]


def fp_matrix(mat, prec=DEFAULT_PRECISION):
    return [fp_vector(x, prec) for x in mat]


def retrieve_fp(scalar, prec=DEFAULT_PRECISION):
    return scalar / (2 ** prec)


def retrieve_fp_vector(vec, prec=DEFAULT_PRECISION):
    return [retrieve_fp(x, prec) for x in vec]


def retrieve_fp_matrix(mat, prec=DEFAULT_PRECISION):
    return [retrieve_fp_vector(x, prec) for x in mat]


class Client:
    def __init__(self, l=DEFAULT_MSGSIZE):
        self.l = l

        # Load public key
        filepub = "Keys/pubkey" + str(DEFAULT_KEYSIZE) + ".txt"
        with open(filepub, 'r') as fin:
            data = [line.split() for line in fin]
        Np = mpz(data[0][0])

        # Reconstruct Paillier public and private keys
        mpk = PaillierPublicKey(n=Np)
        pubkey = labhe.LabHEPublicKey(mpk)
        self.pubkey = pubkey

        filepriv = "Keys/privkey" + str(DEFAULT_KEYSIZE) + ".txt"
        with open(filepriv, 'r') as fin:
            data = [line.split() for line in fin]
        p = mpz(data[0][0])
        q = mpz(data[1][0])

        # Construct Paillier private key using the Paillier public key (mpk)
        msk = PaillierPrivateKey(mpk, p, q)

        # Create a small random user secret key vector (usk) and encrypt to form upk
        # (don't reuse p as the user secret)
        usk = [random.randint(1, 1000) for _ in range(5)]
        upk = util_fpv.encrypt_vector(mpk, usk)
        self.privkey = labhe.LabHEPrivateKey(msk, upk)


    def load_data(self, n, m, N):
        # Load initial state x0
        fileparam = f"Data/x0{n}_{m}_{N}.txt"
        x0 = np.loadtxt(fileparam)
        self.x0 = x0
        self.enc_x0 = encrypt_vector(self.pubkey, fp_vector(x0))

        # Load constraint matrix w0 and compute hu, lu
        filew0 = f"Data/w0{n}_{m}_{N}.txt"
        w0 = np.loadtxt(filew0, delimiter=',')
        hu = np.concatenate([w0[2 * i * m:(2 * i + 1) * m] for i in range(N)])
        lu = np.concatenate([-w0[(2 * i + 1) * m:2 * (i + 1) * m] for i in range(N)])
        self.hu = hu
        self.lu = lu

        # Load dynamics matrices A and B
        fileA = f"Data/A{n}_{m}_{N}.txt"
        self.A = np.loadtxt(fileA, delimiter=',')

        fileB = f"Data/B{n}_{m}_{N}.txt"
        self.B = np.loadtxt(fileB, delimiter=',')

    def closed_loop(self, u):
        u = retrieve_fp_vector(decrypt_vector(self.privkey, u))
        print("Last input: ", ["%.8f" % i for i in u])
        with np.errstate(invalid='ignore'):
            self.x0 = np.dot(self.A, self.x0) + np.dot(self.B, u)
        print("Next state: ", ["%.8f" % i for i in self.x0])
        self.enc_x0 = encrypt_vector(self.pubkey, fp_vector(self.x0))


class Server1:
    def __init__(self, n, m, N, T, l=DEFAULT_MSGSIZE, sigma=DEFAULT_SECURITYSIZE):
        self.l = l
        self.sigma = sigma

        filepub = "Keys/pubkey" + str(DEFAULT_KEYSIZE) + ".txt"
        with open(filepub, 'r') as fin:
            data = [line.split() for line in fin]

        Np = mpz(data[0][0])
        self.Np = Np

        mpk = PaillierPublicKey(n=Np)  # Construct PaillierPublicKey from Np
        pubkey = labhe.LabHEPublicKey(mpk)
        self.pubkey = pubkey
        self.N_len = Np.bit_length()

        fileH = "Data/H" + str(n) + "_" + str(m) + "_" + str(N) + ".txt"
        H = np.loadtxt(fileH, delimiter=',')

        fileF = "Data/F" + str(n) + "_" + str(m) + "_" + str(N) + ".txt"
        F = np.loadtxt(fileF, delimiter=',')

        fileG0 = "Data/G0" + str(n) + "_" + str(m) + "_" + str(N) + ".txt"
        G0 = np.loadtxt(fileG0, delimiter=',')

        fileK = "Data/K" + str(n) + "_" + str(m) + "_" + str(N) + ".txt"
        K = np.loadtxt(fileK, delimiter=',')

        Kc = K[0]
        Kw = K[1]
        self.Kc = int(Kc)
        self.Kw = int(Kw)
        self.T = T
        self.m = m

        nc = m * N
        self.nc = nc

        Hq = Q_matrix(H)
        eigs = np.linalg.eigvals(Hq)
        L = np.real(max(eigs))
        mu = np.real(min(eigs))
        cond = Q_s(L / mu)
        eta = Q_s((np.sqrt(cond) - 1) / (np.sqrt(cond) + 1))
        Hf = Q_matrix([[h / Q_s(L) for h in hv] for hv in Hq])
        Ft = F.transpose()
        Ff = Q_matrix([[Q_s(h) / Q_s(L) for h in hv] for hv in Ft])

        self.eta = eta
        self.Hf = Hf

        mFf = np.negative(Ff)
        self.mFft = fp_matrix(mFf, 2 * DEFAULT_PRECISION)

        coeff_z = np.eye(nc) - Hf
        self.coeff_z = fp_matrix(coeff_z)

    def gen_rands(self, DGK_pubkey):
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
            with open(filePath) as file:
                # Noise for updating the iterate
                rn1 = [[[int(next(file)), int(next(file))] for x in range(0, 2 * nc)] for y in range(0, Kc + (T - 1) * Kw)]
                # Noise for comparison
                rn2 = [[int(next(file)) for x in range(0, nc)] for y in range(0, 2 * Kc + 2 * (T - 1) * Kw)]
        else:
            rn1 = [[[gmpy2.mpz_urandomb(random_state, l + sigma), gmpy2.mpz_urandomb(random_state, l + sigma)] for i in range(0, 2 * nc)] for k in range(0, Kc + (T - 1) * Kw)]
            rn2 = [[gmpy2.mpz_urandomb(random_state, l + sigma) for i in range(0, nc)] for k in range(0, 2 * Kc + 2 * (T - 1) * Kw)]
        self.obfuscations = rn1
        self.rn = rn2
        # Noise for Paillier encryption
        filePath = Path('Randomness/' + str(self.N_len) + '.txt')
        if filePath.is_file():
            with open(filePath) as file:
                coinsP = [int(next(file)) for x in range(0, 4 * (T - 1) * nc * Kw + 4 * nc * Kc)]
        else:
            coinsP = [gmpy2.mpz_urandomb(random_state, self.N_len - 1) for i in range(0, 4 * (T - 1) * nc * Kw + 4 * nc * Kc)]
        coinsP = [gmpy2.powmod(x, self.Np, self.pubkey.nsquare) for x in coinsP]
        # Noise for DGK encryption
        filePath = Path('Randomness/' + str(2 * DEFAULT_DGK) + '.txt')
        if filePath.is_file():
            with open(filePath) as file:
                coinsDGK = [int(next(file)) for x in range(0, 3 * (l + 1) * nc * Kc + 3 * (l + 1) * nc * Kw * (T - 1))]
        else:
            coinsDGK = [gmpy2.mpz_urandomb(random_state, 2 * DEFAULT_DGK) for i in range(0, 3 * (l + 1) * nc * Kc + 3 * (l + 1) * nc * Kw * (T - 1))]
        coinsDGK = [gmpy2.powmod(self.DGK_pubkey.h, x, self.DGK_pubkey.n) for x in coinsDGK]
        self.coinsDGK = coinsDGK
        # Noise for truncation
        filePath = Path('Randomness/' + str(l + 2 * lf + sigma) + '.txt')
        if filePath.is_file():
            with open(filePath) as file:
                rn = [int(next(file)) for x in range(0, nc * Kc + nc * Kw * (T - 1))]
        else:
            rn = [gmpy2.mpz_urandomb(random_state, l + 2 * lf + sigma) for i in range(0, nc * Kc + nc * Kw * (T - 1))]
        self.fixedNoise = encrypt_vector(self.pubkey, rn)  # ,coinsP[-2*nc*K:])
        er = [-fp(x, -2 * lf) for x in rn]
        er = encrypt_vector(self.pubkey, er)  # coinsP[-2*nc*K:-nc*K])
        self.er = er
        # coinsP = coinsP[:-3*nc*K]
        self.coinsP = coinsP

    def compute_coeff(self, x0):
        coeff_0 = np.dot(self.mFft, x0)
        self.coeff_0 = coeff_0

    def t_iterate(self, z):
        return sum_encrypted_vectors(np.dot(self.coeff_z, z), self.coeff_0)

    def z_iterate(self, new_U, U):
        new_z = [fp(1 + self.eta) * v for v in new_U]
        z = [fp(-self.eta) * v for v in U]
        return sum_encrypted_vectors(new_z, z)

    def temporary_prec_t(self):
        nc = self.nc
        pubkey = self.pubkey
        r = [self.fixedNoise.pop() for i in range(0, nc)]
        temp_t = sum_encrypted_vectors(self.t, r)
        return temp_t

    def randomize(self, limit):
        nc = self.nc
        a = [0] * nc
        b = [0] * nc
        for i in range(0, nc):
            a[i], b[i] = np.random.permutation([limit[i] + self.pubkey.encrypt(0), self.t[i]])
        self.a = a
        self.b = b
        return self.a, self.b

    def init_comparison_s1(self, limit):
        nc = self.nc
        l = self.l
        pubkey = self.pubkey
        r = self.r
        a, b = self.randomize(limit)
        z = diff_encrypted_vectors(b, a)
        z = sum_encrypted_vectors(z, encrypt_vector(pubkey, r, self.coinsP[-nc:]))
        z = sum_encrypted_vectors(z, encrypt_vector(pubkey, [2 ** l] * nc, self.coinsP[-2 * nc:-nc]))
        self.coinsP = self.coinsP[:-2 * nc]
        alpha = [gmpy2.t_mod_2exp(x, l) for x in r]
        alpha = [x.digits(2) for x in alpha]
        for i in range(0, nc):
            if (len(alpha[i]) < l):
                alpha[i] = "".join(['0' * (l - len(alpha[i])), alpha[i]])
        self.alpha = alpha
        return z

    def obfuscate(self):
        nc = self.nc
        self.a2 = [0] * nc
        self.b2 = [0] * nc
        for i in range(0, nc):
            r = self.obfuscation[i]
            self.a2[i] = self.a[i] + self.pubkey.encrypt(r[0])
            self.b2[i] = self.b[i] + self.pubkey.encrypt(r[1])
        return self.a2, self.b2

    def update_max(self, v):
        new_U = [0] * self.nc
        for i in range(0, self.nc):
            r = self.obfuscation[i]
            new_U[i] = v[i] + (self.t_comp[i] - 1) * r[0] + self.t_comp[i] * (-r[1])
        return new_U

    def update_min(self, v):
        t = [0] * self.nc
        for i in range(0, self.nc):
            r = self.obfuscation[i]
            t[i] = v[i] + (self.t_comp[i] - 1) * r[1] + self.t_comp[i] * (-r[0])
        return t

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
                if (int(alpha[i]) == 0):
                    prod[i] = beta[i]
                else:
                    prod[i] = DGK.diff_encrypted(DGK_pubkey.raw_encrypt(1, self.coinsDGK.pop()), beta[i], DGK_pubkey)
                if (int(delta_A) == int(alpha[i])):
                    if i == 0:
                        c[i] = DGK_pubkey.raw_encrypt(0, self.coinsDGK.pop())
                    else:
                        for iter in range(0, i):
                            c[i] = DGK.add_encrypted(c[i], prod[iter], DGK_pubkey)
                    if (int(delta_A) == 0):
                        diff = DGK.diff_encrypted(DGK_pubkey.raw_encrypt(1, self.coinsDGK.pop()), beta[i], DGK_pubkey)
                        c[i] = DGK.add_encrypted(c[i], diff, DGK_pubkey)
                    else:
                        c[i] = DGK.add_encrypted(c[i], beta[i], DGK_pubkey)
            for i in range(0, l):
                if (int(delta_A) == int(alpha[i])):
                    r = gmpy2.mpz_urandomb(gmpy2.random_state(), self.sigma + self.sigma)
                    c[i] = DGK.mul_sc_encrypted(c[i], r, DGK_pubkey)
                else:
                    c[i] = DGK_pubkey.raw_encrypt(gmpy2.mpz_urandomb(gmpy2.random_state(), self.sigma + self.sigma), self.coinsDGK.pop())
            c_all[k] = np.random.permutation(c)
        return c_all

    def compute_tDGK(self, delta_B, zdivl):
        t_comp = [0] * self.nc
        for i in range(0, self.nc):
            if (self.delta_A[i] == 1):
                t_comp[i] = delta_B[i]
            else:
                t_comp[i] = self.pubkey.encrypt(1) - delta_B[i]
            t_comp[i] = zdivl[i] - self.pubkey.encrypt(mpz(gmpy2.t_div_2exp(self.r[i], self.l))) - t_comp[i]
        self.t_comp = t_comp
        return t_comp


def key(serialised):
    received_dict = json.loads(serialised)
    pk = received_dict['public_key_DGK']
    n = mpz(pk['n']); g = mpz(pk['g']); h = mpz(pk['h']); u = mpz(pk['u']);
    DGK_pubkey = DGK.DGKpubkey(n=n, g=g, h=h, u=u)
    return DGK_pubkey


import time
import json
import numbers
try:
    from gmpy2 import mpz as _mpz_type
except Exception:
    _mpz_type = None


def send_encr_data(encrypted_number_list):
    """
    Serialize a list of encrypted numbers into JSON-ready list of [c0, c1] string pairs.
    Works whether each encrypted number exposes .ciphertext as a method or property,
    and whether the ciphertext is a single integer or a (c0, c1) pair.
    """
    time.sleep(NETWORK_DELAY)
    out = []

    for x in encrypted_number_list:
        # call ciphertext if it's a method, otherwise access property
        ct = x.ciphertext() if callable(getattr(x, "ciphertext", None)) else getattr(x, "ciphertext", None)

        # If ct is an mpz or int-like single value, treat as (c0, 0)
        if isinstance(ct, (int,)) or (_mpz_type is not None and isinstance(ct, _mpz_type)) or isinstance(ct, numbers.Integral):
            c0 = int(ct)
            c1 = 0
        else:
            # It might be a tuple/list (c0, c1)
            # Some implementations return (EncryptedNumber, EncryptedNumber) or (int, EncryptedNumber) etc.
            if isinstance(ct, (tuple, list)) and len(ct) == 2:
                # convert both parts to ints if possible (EncryptedNumber -> its integer ciphertext is already handled on receiver)
                try:
                    # if elements are mpz or ints
                    c0 = int(ct[0])
                    c1 = int(ct[1])
                except Exception:
                    # fallback: convert to string representation so receiver can parse with ast.literal_eval or handle it
                    c0 = str(ct[0])
                    c1 = str(ct[1])
            else:
                # Last-resort: stringify whatever we got
                c0 = str(ct)
                c1 = 0

        out.append([str(c0), str(c1)])

    return json.dumps(out)


def send_plain_data(data):
    time.sleep(NETWORK_DELAY)
    return json.dumps([str(x) for x in data])


def recv_size(the_socket):
    # data length 4 bytes
    total_len = 0; total_data = []; size = sys.maxsize
    size_data = sock_data = bytes([]); chunk_size = 4096
    while total_len < size:
        sock_data = the_socket.recv(chunk_size)
        if not total_data:
            if len(sock_data) > 4:
                size = struct.unpack('>i', sock_data[:4])[0]
                chunk_size = size
                if chunk_size > 262144: chunk_size = 262144
                total_data.append(sock_data[4:])
            else:
                size_data += sock_data

        else:
            total_data.append(sock_data)
        total_len = sum([len(i) for i in total_data])
    return b''.join(total_data)


import json
import ast
try:
    from gmpy2 import mpz as _mpz_type
except Exception:
    _mpz_type = None


def get_enc_data(received_json, pubkey):
    """
    Parse JSON produced by send_encr_data and return list of LabEncryptedNumber or Paillier encrypted wrappers.
    `received_json` can already be a Python list or a JSON string.
    """
    # If a JSON string, parse it
    if isinstance(received_json, str):
        data = json.loads(received_json)
    else:
        data = received_json

    result = []
    for item in data:
        # Expect item == [c0_str, c1_str] per send_encr_data
        if isinstance(item, (list, tuple)) and len(item) == 2:
            s0, s1 = item[0], item[1]
            # try convert s0/s1 to int (they were emitted as strings)
            try:
                c0 = int(s0)
            except Exception:
                # maybe a long repr: try ast.literal_eval
                try:
                    c0 = ast.literal_eval(s0)
                except Exception:
                    raise ValueError(f"Cannot parse ciphertext element: {s0}")
            try:
                c1 = int(s1)
            except Exception:
                try:
                    c1 = ast.literal_eval(s1)
                except Exception:
                    # if the sender stringified a Paillier EncryptedNumber or LabEncryptedNumber object, you'll need a different
                    # protocol — here we'll just raise a helpful error.
                    raise ValueError(f"Cannot parse ciphertext element: {s1}")

            # Now create LabEncryptedNumber or Paillier Encrypted Number depending on your expected format.
            # If using LabHE two-component ciphertexts, convert to LabEncryptedNumber:
            try:
                import labhe
                # If c1 == 0 this might be a single-component encryption; still wrap as LabEncryptedNumber if you expect LabHE.
                result.append(labhe.LabEncryptedNumber(pubkey, (c0, c1)))
            except Exception:
                # fallback: return raw ints
                result.append((c0, c1))
        else:
            raise ValueError("Received unexpected encryption format; expected list of [c0, c1].")

    return result


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


def get_comp_data(received_dict):
    return [mpz(x) for x in received_dict]


def get_comp_matrix(received_dict):
    return [[mpz(y) for y in x] for x in received_dict]


def main():

    lf = DEFAULT_PRECISION
    n = 5
    m = 5
    N = 7
    T = 1
    s1 = Server1(n, m, N, T)
    s1.Kc = 50; s1.Kw = 20
    Kc = s1.Kc; Kw = s1.Kw
    nc = s1.nc
    pubkey = s1.pubkey
    U = [0] * nc

    client = Client()
    client.n = n; client.m = m; client.N = N; client.Kc = Kc; client.Kw = Kw; client.T = T
    client.nc = nc
    client.load_data(n, m, N)

    s1.hu = encrypt_vector(client.pubkey, fp_vector(client.hu))
    s1.lu = encrypt_vector(client.pubkey, fp_vector(client.lu))

    # TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 10000

    # Connect the socket to the port
    localhost = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1],
                             [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    server_address = (localhost, port)
    print('Server1: Connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    cont = 1
    try:
        while cont:
            # Send n,m,N,Kc,Kw,T
            data = send_plain_data([n, m, N, Kc, Kw, T])
            sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
            U = encrypt_vector(pubkey, fp_vector(U))
            z = [uz * (2 ** lf) for uz in U]
            K = Kc
            # Get DGK_pubkey
            data = recv_size(sock)
            DGK_pubkey = key(data)
            s1.gen_rands(DGK_pubkey)
            sec = [0] * T
            time_s1 = [0] * K
            time_s2 = [0] * K

            start = time.time()
            # Time steps
            for i in range(0, T):
                # print("i = ", i)
                x0 = client.enc_x0
                s1.compute_coeff(x0)
                # Optimization steps
                for k in range(0, K):
                    # print("k = ", k)
                    start_s1 = time.time()
                    s1.t = s1.t_iterate(z)
                    s1.obfuscation = s1.obfuscations[k]
                    s1.r = s1.rn[k]
                    temp_t = s1.temporary_prec_t()
                    # Send temp_t to the target
                    data = send_encr_data(temp_t)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive [(temp_t + r)*2^{-2lf}]
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    temp_tr = get_enc_data(data, pubkey)
                    s1.t = sum_encrypted_vectors(temp_tr, [s1.er.pop() for i in range(0, nc)])  # t = int(t*2**16)

                    # Projection on hu
                    # Send z_DGK
                    z_DGK = s1.init_comparison_s1(s1.hu)
                    data = send_encr_data(z_DGK)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive b
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    b = get_comp_matrix(data)
                    c = s1.DGK_s1(b)
                    # Send c
                    serialized_data = send_DGK_matrix(c)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive delta_B, zvdil
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    merged = get_enc_data(data, pubkey)
                    delta_B = merged[:nc]; zdivl = merged[nc:]
                    t_comp = s1.compute_tDGK(delta_B, zdivl)
                    # Send t_comp,a2,b2
                    a2, b2 = s1.obfuscate()
                    data = send_encr_data(t_comp + a2 + b2)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive v
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    v = get_enc_data(data, pubkey)
                    s1.t = s1.update_min(v)

                    # Projection on lu
                    # Send z_DGK
                    z_DGK = s1.init_comparison_s1(s1.lu)
                    data = send_encr_data(z_DGK)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive b
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    b = get_comp_matrix(data)
                    c = s1.DGK_s1(b)
                    # Send c
                    serialized_data = send_DGK_matrix(c)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(serialized_data)) + serialized_data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive delta_B, zvdil
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    merged = get_enc_data(data, pubkey)
                    delta_B = merged[:nc]; zdivl = merged[nc:]
                    t_comp = s1.compute_tDGK(delta_B, zdivl)
                    # Send t,a2,b2
                    a2, b2 = s1.obfuscate()
                    data = send_encr_data(t_comp + a2 + b2)
                    time_s1[k] += time.time() - start_s1
                    sock.sendall(struct.pack('>i', len(data)) + data.encode('utf-8'))
                    start_s2 = time.time()
                    # Receive v
                    data = json.loads(recv_size(sock))
                    time_s2[k] += time.time() - start_s2
                    start_s1 = time.time()
                    v = get_enc_data(data, pubkey)
                    new_U = s1.update_max(v)  # [[U_{k+1}]]

                    #  New [[U_{k+1}]]
                    z = s1.z_iterate(new_U, U)
                    U = new_U
                    time_s1[k] += time.time() - start_s1
                u = U[:m]
                client.closed_loop(u);
                U = list(U[m:]) + list([pubkey.encrypt(0)] * m)
                z = [el * 2 ** lf for el in U]
                K = Kw
                sec[i] = time.time() - start
                start = time.time()
            print('total time', sec)
            with open(os.path.abspath(str(DEFAULT_KEYSIZE) + '_' + str(DEFAULT_PRECISION) + '_results_SS' + '.txt'), 'a+') as f:
                f.write("%d, %d, %d, %d, %d, %d: " % (n, m, N, Kc, Kw, T));
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
