# Schnorr signature

import dumb25519
from dumb25519 import Scalar, Point, random_scalar, hash_to_scalar, G, Z

# Schnorr signature
class Signature:
    s = None
    e = None

# Generate a Schnorr signature
def sign(m,x):
    if x == Scalar(0):
        raise ValueError('Private key must be nonzero!')
    X = G*x # public key

    k = Scalar(0)
    while k == Scalar(0):
        k = random_scalar()
    K = G*k

    sig = Signature()
    sig.e = hash_to_scalar(K,m)
    sig.s = k - x*sig.e

    return sig

# Verify a Schnorr signature
def verify(m,X,sig):
    if X == Z:
        raise ValueError('Public key must be nonzero!')

    K = G*sig.s + X*sig.e
    e = hash_to_scalar(K,m)

    if not e == sig.e:
        raise ArithmeticError('Bad Shnorr signature!')
    return True
