import socket
import struct
import json
from gmpy2 import mpz
import labhe


def recv_size(sock):
    total_len = 0
    total_data = []
    size = struct.unpack('>i', sock.recv(4))[0]
    while total_len < size:
        packet = sock.recv(min(4096, size - total_len))
        if not packet:
            break
        total_data.append(packet)
        total_len += len(packet)
    return b''.join(total_data)


def send_json(sock, obj):
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack('>i', len(payload)) + payload)


def main():
    print("Server2: Initializing...")
    privkey, pubkey = labhe.Init(512)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 10000))
    sock.listen(1)
    print("Server2: Listening on port 10000...")

    conn1, addr1 = sock.accept()
    print("Server2: Connected to Server1.")

    while True:
        try:
            data = recv_size(conn1)
            if not data:
                break

            msg = json.loads(data.decode())

            if isinstance(msg, list) and 'label' in msg[0]:
                ctxts = [labhe.Ciphertext(e['label'], mpz(e['ciphertext'])) for e in msg]
                decrypted = [labhe.decrypt(privkey, c) for c in ctxts]
                re_encrypted = [
                    {
                        'label': c.label,
                        'ciphertext': str(labhe.encrypt(x, label=c.label, lf=16).ciphertext)
                    } for c, x in zip(ctxts, decrypted)
                ]
                send_json(conn1, re_encrypted)
                print("Server2: Sent re-encrypted u + rho")

            elif isinstance(msg, dict) and all(k in msg for k in ['a', 'b', 'r', 's']):
                a_ctxt = labhe.Ciphertext(msg['a']['label'], mpz(msg['a']['ciphertext']))
                b_ctxt = labhe.Ciphertext(msg['b']['label'], mpz(msg['b']['ciphertext']))

                a_blinded = labhe.decrypt(privkey, a_ctxt)
                b_blinded = labhe.decrypt(privkey, b_ctxt)

                r = float(msg['r'])
                s = float(msg['s'])

                if a_blinded <= b_blinded:
                    beta = 1
                    v = a_blinded
                    label = a_ctxt.label
                else:
                    beta = 0
                    v = b_blinded
                    label = b_ctxt.label

                v_enc = labhe.encrypt(val=v, label=label, lf=16)
                resp = {
                    'beta': beta,
                    'label': v_enc.label,
                    'ciphertext': str(v_enc.ciphertext)
                }
                send_json(conn1, resp)
                print(f"Server2: Sent comparison result beta={beta}, label={v_enc.label}")

        except Exception as e:
            print("Server2: Exception occurred:", e)
            break

    conn1.close()
    sock.close()
    print("Server2: Closed connection.")


if __name__ == '__main__':
    main()
