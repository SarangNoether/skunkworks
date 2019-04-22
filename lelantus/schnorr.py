# Generalized Schnorr proof
#
# Shows that the prover knows s,t such that Y = s*G + t*H for public Y,G,H

from common import *
from dumb25519 import Scalar, Point, random_scalar, hash_to_scalar

# Schnorr proof
class Proof:
    W = None
    X = None
    Y = None
    U = None
    s1 = None
    t1 = None

# Perform a generalized Schnorr proof
def prove(s,t,W,X):
    Y = W*s + X*t
    cache = '' # Fiat-Shamir rolling transcript hash
    
    s0 = random_scalar()
    t0 = random_scalar()
    U = W*s0 + X*t0

    # Update transcript
    cache = hash_to_scalar(cache,W)
    cache = hash_to_scalar(cache,X)
    cache = hash_to_scalar(cache,Y)
    cache = hash_to_scalar(cache,U)

    x = cache # challenge
    s1 = s0 - x*s
    t1 = t0 - x*t

    proof = Proof()
    proof.W = W
    proof.X = X
    proof.Y = Y
    proof.U = U
    proof.s1 = s1
    proof.t1 = t1
    return proof

# Verify a generalized Schnorr proof
def verify(proof):
    cache = '' # Fiat-Shamir rolling transcript hash

    # Update transcript
    cache = hash_to_scalar(cache,proof.W)
    cache = hash_to_scalar(cache,proof.X)
    cache = hash_to_scalar(cache,proof.Y)
    cache = hash_to_scalar(cache,proof.U)

    x = cache # challenge

    if not proof.U == proof.Y*x + proof.s1*proof.W + proof.t1*proof.X:
        raise ArithmeticError('Invalid proof!')
    return True
