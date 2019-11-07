# Schnorr signature

from common import *
from dumb25519 import Scalar, Point, random_scalar, hash_to_scalar, Z

# Schnorr signature
class Signature:
    def __init__(self):
        self.s = None
        self.e = None

    def __repr__(self):
        r = '<Signature> '
        r += 's:' + repr(self.s) + '|'
        r += 'e:' + repr(self.e)
        return r

# Generate a Schnorr signature
def sign(m,x,B):
    if x == Scalar(0):
        raise ValueError('Private key must be nonzero!')
    X = B*x # public key

    k = Scalar(0)
    while k == Scalar(0):
        k = random_scalar()
    K = B*k

    sig = Signature()
    sig.e = hash_to_scalar(K,m,B)
    sig.s = k - x*sig.e

    return sig

# Verify a Schnorr signature
def verify(m,X,sig,B):
    if X == Z:
        raise ValueError('Public key must be nonzero!')

    K = B*sig.s + X*sig.e
    e = hash_to_scalar(K,m,B)

    if not e == sig.e:
        raise ArithmeticError('Bad Shnorr signature!')
    return True
