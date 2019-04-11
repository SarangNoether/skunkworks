# Generalized Schnorr proof
#
# Shows that the prover knows s,t such that Y = s*G + t*H for public Y,G,H

import dumb25519
from dumb25519 import Scalar, Point, random_scalar, hash_to_scalar

# Schnorr proof
class Proof:
    G = None
    H = None
    Y = None
    U = None
    s1 = None
    t1 = None

# Perform a generalized Schnorr proof
def prove(s,t,G,H):
    Y = G*s + H*t
    cache = '' # Fiat-Shamir rolling transcript hash
    
    s0 = random_scalar()
    t0 = random_scalar()
    U = G*s0 + H*t0

    # Update transcript
    cache = hash_to_scalar(cache,G)
    cache = hash_to_scalar(cache,H)
    cache = hash_to_scalar(cache,Y)
    cache = hash_to_scalar(cache,U)

    x = cache # challenge
    s1 = s0 - x*s
    t1 = t0 - x*t

    proof = Proof()
    proof.G = G
    proof.H = H
    proof.Y = Y
    proof.U = U
    proof.s1 = s1
    proof.t1 = t1
    return proof

# Verify a generalized Schnorr proof
def verify(proof):
    cache = '' # Fiat-Shamir rolling transcript hash

    # Update transcript
    cache = hash_to_scalar(cache,proof.G)
    cache = hash_to_scalar(cache,proof.H)
    cache = hash_to_scalar(cache,proof.Y)
    cache = hash_to_scalar(cache,proof.U)

    x = cache # challenge

    if not proof.U == proof.Y*x + proof.s1*proof.G + proof.t1*proof.H:
        raise ArithmeticError('Invalid proof!')
    return True
