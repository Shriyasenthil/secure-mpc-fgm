import socket
import struct
import json
import numpy as np
from gmpy2 import mpz
import labhe
from utils import he_matvec_mul_precise, zero_vector, control_scalar_mult_fixed

def recv_size(sock):
    size_data = b''
    while len(size_data) < 4:
        packet = sock.recv(4 - len(size_data))
        if not packet:
            raise ConnectionError("Connection closed while reading message size.")
        size_data += packet
    size = struct.unpack('>i', size_data)[0]

    data = b''
    while len(data) < size:
        packet = sock.recv(min(4096, size - len(data)))
        if not packet:
            raise ConnectionError("Connection closed while reading message body.")
        data += packet
    return data

def recv_data(sock):
    size_data = sock.recv(4)
    if len(size_data) < 4:
        raise ConnectionError("Incomplete message size received.")
    size = struct.unpack('>i', size_data)[0]
    data = b''
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection closed while receiving data.")
        data += packet
    return json.loads(data.decode())

def send_json(sock, obj):
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack('>i', len(payload)) + payload)

def secure_min_projection(tk_vec, hu_vec, sock2, lf):
    result = []
    for a_ct, b_ct in zip(tk_vec, hu_vec):
        r = np.random.uniform(-1, 1)
        s = np.random.uniform(-1, 1)

        r_enc = labhe.encrypt(val=r, label=a_ct.label, lf=lf)
        s_enc = labhe.encrypt(val=s, label=b_ct.label, lf=lf)

        a_blinded = labhe.Eval_add(labhe.pubkey, a_ct, r_enc)
        b_blinded = labhe.Eval_add(labhe.pubkey, b_ct, s_enc)

        send_json(sock2, {
            "a": {"label": a_blinded.label, "ciphertext": str(a_blinded.ciphertext)},
            "b": {"label": b_blinded.label, "ciphertext": str(b_blinded.ciphertext)},
            "r": r,
            "s": s
        })

        resp = recv_size(sock2)
        payload = json.loads(resp.decode())
        v_enc = labhe.Ciphertext(payload['label'], mpz(payload['ciphertext']))
        beta = payload['beta']

        if beta == 1:
            v_final = labhe.Eval_add(labhe.pubkey, v_enc, labhe.encrypt(val=-r, label=v_enc.label, lf=lf))
        else:
            v_final = labhe.Eval_add(labhe.pubkey, v_enc, labhe.encrypt(val=-s, label=v_enc.label, lf=lf))

        result.append(v_final)
    return result

def secure_max_projection(tk_vec, lu_vec, sock2, lf):
    result = []
    for a_ct, b_ct in zip(tk_vec, lu_vec):
        r = np.random.uniform(-1, 1)
        s = np.random.uniform(-1, 1)

        r_enc = labhe.encrypt(val=r, label=a_ct.label, lf=lf)
        s_enc = labhe.encrypt(val=s, label=b_ct.label, lf=lf)

        a_blinded = labhe.Eval_add(labhe.pubkey, a_ct, r_enc)
        b_blinded = labhe.Eval_add(labhe.pubkey, b_ct, s_enc)

        send_json(sock2, {
            "a": {"label": a_blinded.label, "ciphertext": str(a_blinded.ciphertext)},
            "b": {"label": b_blinded.label, "ciphertext": str(b_blinded.ciphertext)},
            "r": r,
            "s": s
        })

        resp = recv_size(sock2)
        payload = json.loads(resp.decode())
        v_enc = labhe.Ciphertext(payload['label'], mpz(payload['ciphertext']))
        beta = payload['beta']

        if beta == 1:
            v_final = labhe.Eval_add(labhe.pubkey, v_enc, labhe.encrypt(val=-s, label=v_enc.label, lf=lf))
        else:
            v_final = labhe.Eval_add(labhe.pubkey, v_enc, labhe.encrypt(val=-r, label=v_enc.label, lf=lf))

        result.append(v_final)
    return result

def debug_decrypt_values(privkey, ciphertexts, lf, name):
    print(f"\n=== Debug {name} ===")
    for i, ct in enumerate(ciphertexts):
        try:
            decoded = labhe.D(privkey, ct)
            bit_length = decoded.bit_length()
            print(f"{name}[{i}] raw decoded bit length: {bit_length}")
            if bit_length < 200:
                print(f"{name}[{i}] raw decoded = {decoded}")
            else:
                print(f"{name}[{i}] raw decoded = <too large to display>")

            scaling_factor = mpz(1 << lf)
            original_val_mpz = decoded // scaling_factor
            remainder = decoded % scaling_factor
            if abs(original_val_mpz) < 10**15:
                original_val = float(original_val_mpz) + float(remainder) / float(scaling_factor)
                print(f"{name}[{i}] with lf={lf}: {original_val}")
            else:
                print(f"{name}[{i}] with lf={lf}: Value too large for float conversion")
        except Exception as e:
            print(f"  ❌ Error decrypting {name}[{i}]: {e}")

def main():
    lf = 16
    Nm = 2
    K = 3

    privkey, pubkey = labhe.Init(2048)
    labhe.privkey = privkey
    labhe.pubkey = pubkey

    H_bar = np.array([[0.5, 0.2], [-0.1, 0.8]])
    F_bar = np.array([[0.3, 0.4], [0.1, 0.6]])

    hu = [1.0 for _ in range(Nm)]
    lu = [-1.0 for _ in range(Nm)]

    sock_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 10001
    sock_c.bind(('localhost', port))
    sock_c.listen(1)
    print(f"Server1: Listening on port {port}...")

    conn_c, addr_c = sock_c.accept()
    print(f"Server1: Connected to Client at {addr_c}")

    enc_payload = recv_data(conn_c)
    enc_xt = [labhe.Ciphertext(e['label'], mpz(e['ciphertext'])) for e in enc_payload]
    print("Server1: Received encrypted x(t)")

    sock_s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_s2.connect(('localhost', 10000))
    print("Server1: Connected to Server2")

    U0 = zero_vector(Nm, pubkey, lf)
    zk = U0
    zk_prev = zk

    hu_enc = [labhe.encrypt(v, label=f"hu_{i}", lf=lf, auto_scale=True) for i, v in enumerate(hu)]
    lu_enc = [labhe.encrypt(v, label=f"lu_{i}", lf=lf, auto_scale=True) for i, v in enumerate(lu)]

    for i, v in enumerate(lu):
        info = labhe.check_value_compatibility(v, lf)
        if not info["compatible"]:
            print(f"lu[{i}] = {v} is too large for lf={lf}. Suggest lf={info['suggested_lf']}")

    for k in range(K):
        I_minus_H = np.identity(Nm) - H_bar
        neg_F = -F_bar

        zk_term = he_matvec_mul_precise(I_minus_H, zk, pubkey, lf)
        xt_term = he_matvec_mul_precise(neg_F, enc_xt, pubkey, lf)
        tk = [labhe.Eval_add(pubkey, a, b) for a, b in zip(zk_term, xt_term)]

        debug_decrypt_values(privkey, tk, lf, "tk")

        tk_max = secure_max_projection(tk, lu_enc, sock_s2, lf)
        debug_decrypt_values(privkey, tk_max, lf, "tk_max")

        Uk1 = secure_min_projection(tk_max, hu_enc, sock_s2, lf)
        debug_decrypt_values(privkey, Uk1, lf, "Uk1")

        zk = []
        for u, z in zip(Uk1, zk_prev):
            term1 = control_scalar_mult_fixed(pubkey, u, 1.1)
            term2 = control_scalar_mult_fixed(pubkey, z, -0.1)
            term1.label = u.label
            term2.label = u.label
            combined = labhe.Eval_add(pubkey, term1, term2)
            zk.append(combined)

        debug_decrypt_values(privkey, zk, lf, "zk")
        zk_prev = zk

    UK_m = zk[:Nm]
    rho = [labhe.encrypt(0, label=u.label, lf=lf) for u in UK_m]
    enc_result = [labhe.Eval_add(pubkey, u, r) for u, r in zip(UK_m, rho)]

    send_json(sock_s2, [{'label': c.label, 'ciphertext': str(c.ciphertext)} for c in enc_result])
    recv_rerand = recv_data(sock_s2)
    rerand = [labhe.Ciphertext(e['label'], mpz(e['ciphertext'])) for e in recv_rerand]

    neg_rho = [labhe.Eval_mult_scalar(pubkey, r, -1) for r in rho]
    final_u = [labhe.Eval_add(pubkey, u, r) for u, r in zip(rerand, neg_rho)]

    send_json(conn_c, [{'label': c.label, 'ciphertext': str(c.ciphertext)} for c in final_u])
    print("Server1: Sent final encrypted u to Client")
    print(f"pubkey.max_int: {pubkey.max_int}")
    print(f"lf value: {lf}")
    print(f"Type of pubkey.max_int: {type(pubkey.max_int)}")
    print(f"hu max: {max(hu)}")
    print(f"hu min: {min(hu)}")
    print(f"hu values: {hu[:5]}...")  # First 5 values

    send_json(sock_s2, {"type": "done"})
    conn_c.close()
    sock_s2.close()
    sock_c.close()

if __name__ == '__main__':
    main()
