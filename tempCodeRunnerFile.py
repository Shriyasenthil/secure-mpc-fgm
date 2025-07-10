
def Init():
    
    from paillier import generate_paillier_keypair
    pubkey, privkey = generate_paillier_keypair()
    return privkey, pubkey



class LabHEPublicKey(object):
   
    def __init__(self, mpk):
        self.Pai_key = mpk
        self.n = mpk.n
        self.max_int = mpk.n // 3 - 1

    @property
    def n_sq(self):
        return self.Pai_key.nsquare  