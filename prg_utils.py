import hashlib

def prg(seed: bytes, length: int = 32) -> bytes:
   
    output = b''
    counter = 0
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, 'big')
        output += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1
    return output[:length]
