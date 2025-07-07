import hashlib
import secrets
import json
import struct
from gmpy2 import mpz

def serialize_ciphertext(ct):
    
    return json.dumps({
        'label': ct.label,
        'ciphertext': str(ct.ciphertext)
    })

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def ot_sender(sock, m0, m1):
   
    
    ct0 = serialize_ciphertext(m0).encode()
    ct1 = serialize_ciphertext(m1).encode()

    
    payload = json.dumps([ct0.decode(), ct1.decode()])
    sock.sendall(struct.pack('>i', len(payload)) + payload.encode('utf-8'))

    print("[OT Sender] Sent OT message pair to receiver.")
