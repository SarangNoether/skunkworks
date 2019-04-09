# Generalized Schnorr proof
#
# Shows that the prover knows s,t such that y = s*G + t*H for public y,G,H

import dumb25519
from dumb25519 import Scalar, Point, random_scalar, hash_to_scalar, hash_to_point

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

    return [G,H,Y,U,s1,t1]

# Verify a generalized Schnorr proof
def verify(proof):
    G,H,Y,U,s1,t1 = proof
    cache = '' # Fiat-Shamir rolling transcript hash

    # Update transcript
    cache = hash_to_scalar(cache,G)
    cache = hash_to_scalar(cache,H)
    cache = hash_to_scalar(cache,Y)
    cache = hash_to_scalar(cache,U)

    x = cache # challenge

    if not U == Y*x + s1*G + t1*H:
        raise ArithmeticError('Invalid proof!')
    return True
