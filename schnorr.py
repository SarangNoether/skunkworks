# Schnorr proof of knowledge

from dumb25519 import *

class SchnorrProof:
    # Generate a proof of knowledge of `w` such that `P == w*Q`
    def __init__(self,w,P,Q):
        if not P == w*Q:
            raise ArithmeticError('Bad Schnorr parameters!')

        k = random_scalar()
        self.c = hash_to_scalar('Schnorr proof',P,Q,k*Q)
        self.s = k - self.c*w

    # Verify the proof
    def verify(self,P,Q):
        if not hash_to_scalar('Schnorr proof',P,Q,self.s*Q + self.c*P) == self.c:
            raise ArithmeticError('Bad Schnorr verification!')

        return True
