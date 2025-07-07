import hashlib
import json
import secrets
import struct
from gmpy2 import mpz
from labhe import Ciphertext, D
from prg_utils import prg  

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def ot_receiver(sock, privkey, choice_bit):
   
    msg_len = struct.unpack('>i', sock.recv(4))[0]
    payload = sock.recv(msg_len)
    messages = json.loads(payload.decode())

    msg0 = json.loads(messages[0]) 
    msg1 = json.loads(messages[1])

    ct0 = Ciphertext(msg0['label'], mpz(msg0['ciphertext']))
    ct1 = Ciphertext(msg1['label'], mpz(msg1['ciphertext']))

    selected_ct = ct1 if choice_bit else ct0

    decrypted = D(privkey, selected_ct)
    return decrypted