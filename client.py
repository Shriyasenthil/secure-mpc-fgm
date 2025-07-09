import socket
import struct
import json
import labhe
import numpy as np
from gmpy2 import mpz
from utils import encrypt_vector, decrypt_vector, fp_vector

def send_json(sock, obj):
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack('>i', len(payload)) + payload)

def recv_data(sock):
    size_data = b''
    while len(size_data) < 4:
        packet = sock.recv(4 - len(size_data))
        if not packet:
            raise ConnectionError("Failed to receive full size header.")
        size_data += packet

    size = struct.unpack('>i', size_data)[0]

    data = b''
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection closed while receiving data.")
        data += packet

    return json.loads(data.decode())

def main():
    privkey, pubkey = labhe.Init(512)
    labhe.privkey = privkey
    labhe.pubkey = pubkey

    x_t = [0.3, -0.2]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 10001))
    print("Client: Connected to Server1")

    try:
        # Encode and encrypt x(t)
        enc_xt = [labhe.encrypt(val, label=f"x_{i}", lf=16, already_encoded=True) for i, val in enumerate(fp_vector(x_t))]

        data = [{'label': c.label, 'ciphertext': str(c.ciphertext)} for c in enc_xt]
        send_json(sock, data)
        print("Client: Sent encrypted x(t) to Server1")

        # Receive and decrypt final result
        result = recv_data(sock)
        enc_u = [labhe.Ciphertext(e['label'], mpz(e['ciphertext'])) for e in result]
        u_fp = decrypt_vector(enc_u, privkey)  # Already returns floating-point values

        print("Client: Decrypted final control vector (floating-point):")
        for i, val in enumerate(u_fp):
            print(f"  u[{i}] = {val:.6f}")
            if abs(val) > 1000:
                print(f" Warning: Unusually large value for u[{i}]")

    finally:
        sock.close()

if __name__ == '__main__':
    main()
