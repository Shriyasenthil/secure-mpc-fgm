
def Init():
    """Initialize LabHE by generating Paillier keypair."""
    from paillier import generate_paillier_keypair
    pubkey, privkey = generate_paillier_keypair()
    return privkey, pubkey



class LabHEPublicKey(object):
    """Composed of PaillierPublicKey 

    Attributes:
      mpk (PaillierPublicKey): the public key of the underlying Paillier scheme
      max_int (int): n/3, the maximum positive value a plaintext can be
    """
    def __init__(self, mpk):
        self.Pai_key = mpk
        self.n = mpk.n
        self.max_int = mpk.n // 3 - 1

    @property
    def n_sq(self):
        return self.Pai_key.nsquare  # ✅ This will fix the AttributeError
