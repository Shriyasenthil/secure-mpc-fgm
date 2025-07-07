import socket
import struct
import json
import numpy as np
from gmpy2 import mpz
import labhe
from utils import he_add, he_scalar_mul, zero_vector, encrypt_vector, decrypt_vector, truncate


def send_data(sock, data):
    payload = json.dumps(data)
    sock.sendall(struct.pack('>i', len(payload)) + payload.encode('utf-8'))


def recv_data(sock):
    size_data = sock.recv(4)
    if not size_data:
        raise ConnectionError("Received empty header (connection closed).")
    size = struct.unpack('>i', size_data)[0]
    data = b''
    while len(data) < size:
        to_read = size - len(data)
        chunk = sock.recv(4096 if to_read > 4096 else to_read)
        if not chunk:
            raise ConnectionError("Incomplete message received.")
        data += chunk
    return json.loads(data.decode())


def he_matvec_mul(mat, enc_vector, pubkey, lf):
    scale = 1 << lf
    result = []
    for i, row in enumerate(mat):
        acc = None
        for j, scalar in enumerate(row):
            if scalar == 0:
                continue
            fixed_scalar = int(round(scalar * scale))
            prod = labhe.Eval_mult_scalar(pubkey, enc_vector[j], mpz(fixed_scalar))
            prod.label = f"row_{i}"
            if acc is None:
                acc = prod
            else:
                acc = labhe.Eval_add(pubkey, acc, prod)
        if acc is None:
            acc = labhe.Eval_mult_scalar(pubkey, enc_vector[0], mpz(0))
            acc.label = f"row_{i}"
        result.append(acc)
    return result


def control_scalar_mult(pubkey, ciphertext, scalar_float):
    if abs(scalar_float - 1.1) < 1e-6:
        return labhe.Eval_mult_scalar(pubkey, ciphertext, 1)
    elif abs(scalar_float - (-0.1)) < 1e-6:
        return labhe.Eval_mult_scalar(pubkey, ciphertext, 0)
    else:
        return labhe.Eval_mult_scalar(pubkey, ciphertext, int(round(scalar_float)))


class FGDServer:
    def __init__(self, H_bar_f, F_bar_f, eta_bar, cold_start, Uw, m, pubkey, privkey, K, lf):
        self.H_bar_f = H_bar_f
        self.F_bar_f = F_bar_f
        self.eta_bar = eta_bar
        self.cold_start = cold_start
        self.Uw = Uw
        self.m = m
        self.pubkey = pubkey
        self.privkey = privkey
        self.K = K
        self.lf = lf
        self.enc_Uk = None
        self.enc_xt = None

    def receive_encrypted_xt(self, enc_xt_objs):
        self.enc_xt = [
            labhe.Ciphertext.from_json(c)
            for c in enc_xt_objs
        ]
        print(f"Server: Received enc_xt with length {len(self.enc_xt)}")
        self.init_U0()

    def init_U0(self):
        N = self.H_bar_f.shape[0]
        print(f"Server: Initializing U0 with N={N}")
        if self.cold_start:
            self.enc_Uk = zero_vector(N, self.pubkey)
        else:
            tail = self.Uw[self.m:]
            self.enc_Uk = encrypt_vector(tail + [0] * self.m, self.pubkey, label='xt')
        self.enc_zk = self.enc_Uk

    def compute_tk(self):
        I_minus_H = np.eye(self.H_bar_f.shape[0]) - self.H_bar_f
        minus_F = -self.F_bar_f
        enc_t1 = he_matvec_mul(I_minus_H, self.enc_zk, self.pubkey, self.lf)
        enc_t2 = he_matvec_mul(minus_F, self.enc_xt, self.pubkey, self.lf)
        if len(enc_t1) != len(enc_t2):
            raise ValueError("Vector length mismatch")
        tk = he_add(enc_t1, enc_t2, self.pubkey)
        return tk

    def update_uk_and_zk(self, enc_Uk_plus1_objs):
        enc_Uk_plus1 = [
            labhe.Ciphertext.from_json(c)
            for c in enc_Uk_plus1_objs
        ]
        for i in range(len(enc_Uk_plus1)):
            enc_Uk_plus1[i].label = self.enc_Uk[i].label
        term1 = [control_scalar_mult(self.pubkey, u, 1.1) for u in enc_Uk_plus1]
        term2 = [control_scalar_mult(self.pubkey, z, -0.1) for z in self.enc_Uk]
        enc_zk_new = he_add(term1, term2, self.pubkey)
        self.enc_Uk = enc_Uk_plus1
        self.enc_zk = enc_zk_new

    def get_final_UK(self):
        return [c.to_json() for c in self.enc_Uk]


def main():
    print("Server: Initializing LabHE...")
    privkey, pubkey = labhe.Init(512)
    upk, _ = labhe.KeyGen(pubkey)
    n, m, N = 5, 5, 35
    cold_start = True
    Uw = [0] * N
    eta_bar = 0.1
    K = 3
    lf = 2
    H = np.loadtxt(f"Data/H{n}_{m}_{N}.txt", delimiter=',')
    F_full = np.loadtxt(f"Data/F{n}_{m}_{N}.txt", delimiter=',')
    F = np.zeros((N, N))
    F[:m, :] = F_full
    print(f"Server: Loaded matrices H: {H.shape}, F: {F.shape}")
    print(f"Sample row from H (first 5 elements): {H[0][:5]}")
    print(f"Sample row from F (first 5 elements): {F[0][:5]}")
    print(f"H range: min={np.min(H)}, max={np.max(H)}")
    print(f"F range: min={np.min(F)}, max={np.max(F)}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('localhost', 10001)
    server_socket.bind(server_address)
    server_socket.listen(1)
    print("Server: Listening on port 10001...")
    conn, client_address = server_socket.accept()
    print("Server: Connected to", client_address)
    server = FGDServer(H, F, eta_bar, cold_start, Uw, m, pubkey, privkey, K, lf)
    try:
        msg = recv_data(conn)
        if msg['type'] == 'xt':
            print("Server: Received [[x(t)]]")
            server.receive_encrypted_xt(msg['data'])
        for k in range(K):
            print(f"Server: Sending [[tk]] for iteration {k}")
            tk = server.compute_tk()
            send_data(conn, {'type': 'tk', 'data': [c.to_json() for c in tk]})
            msg = recv_data(conn)
            if msg['type'] == 'Uk+1':
                print(f"Server: Received [[Uk+1]] at iteration {k}")
                server.update_uk_and_zk(msg['data'])
        print("Server: Sending final [[UK]] to client.")
        final_UK = server.get_final_UK()
        send_data(conn, {'type': 'final', 'data': final_UK})
        Uk_plain = decrypt_vector(server.enc_Uk, server.privkey)
        Uk_trunc = truncate(Uk_plain, lf)
        print("Server1: Final plaintext UK before sending (truncated, first 5):", Uk_trunc[:5])
        print("Server1: Raw mpz final[0]:", Uk_plain[0])
        print("Server1: Type of element:", type(Uk_plain[0]))
    except Exception as e:
        print(f"Server: Error occurred - {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("Server: Closing connection.")
        conn.close()
        server_socket.close()


if __name__ == '__main__':
    main()
