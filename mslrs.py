# MSLRS: AOS-based linkable ring signature
# https://eprint.iacr.org/2020/333
#
# For a ring with members of the form (P_i,C_i) such that (P_l,C_l) = (p*G,z*G)
# for some index l, generates a linkable ring signature on a message such that
# any public key is equiprobable as corresponding to the signing key.
#
# Two valid signatures containing the same key image were signed with the same
# private key, regardless of the other ring members used in the signature.
#
# By providing a PRNG seed value (which _should_ be unique between uses) during
# signing, a verifier with the same seed value can extract the signing index.

from dumb25519 import *

# MSLRS signature
class Signature:
    c0 = None
    s = None
    I = None
    D = None

# Generate a MSLRS signature
# INPUTS
#   M: message
#   p: private key
#   P: public key vector
#   z: commitment private key
#   C: commitment vector
#   seed: PRNG seed (optional)
#   index: if set, bypass key index check (testing only)
# RETURNS
#   sig: Signature
# RAISES
#   IndexError if index is not set and private keys are invalid
def sign(M,p,P,z,C,seed=None,index=None):
    n = len(P) # ring size

    # Recover the private key index
    l = None
    if index is not None:
        l = index
    else:
        for i in range(n):
            if P[i] == p*G and C[i] == z*G:
                l = i
                break
        if l is None:
            raise IndexError('Private keys must correspond to public keys!')

    # Construct key images
    I = p*hash_to_point(P[l])
    D = z*hash_to_point(P[l])

    # Now generate the signature
    e1 = hash_to_scalar('MSLRS e1',M,P,C,I,D)
    e2 = hash_to_scalar('MSLRS e2',M,P,C,I,D)
    c = [None]*n
    r = random_scalar()

    # Scalars are either random (seed is None) or hash-constructed
    if seed is None:
        s = [random_scalar() for _ in range(n)]
    else:
        s = [hash_to_scalar('MSLRS scalar',seed,I,i) for i in range(n)]

    # Private index
    c[(l+1) % n] = hash_to_scalar('MSLRS round',M,P,C,I,D,r*(G + e1*hash_to_point(P[l])))

    # Decoy indices
    if n > 1:
        for i in range(l+1,l+n):
            i = i % n
            c[(i+1) % n] = hash_to_scalar('MSLRS round',M,P,C,I,D,s[i]*(G + e1*hash_to_point(P[i])) - c[i]*(P[i] + e1*I + e2*C[i] + e1*e2*D))

    # Final scalar computation
    s[l] = r + (p + e2*z)*c[l]

    # Assemble the signature
    sig = Signature()
    sig.c0 = c[0]
    sig.s = s
    sig.I = I
    sig.D = D

    return sig

# Verify signature
# INPUTS
#   M: message
#   P: public key vector
#   C: commitment vector
#   sig: Signature
#   seed: PRNG seed (optional)
# RETURNS
#   signing index (or None) if valid
# RAISES
#   ArithmeticError if signature is invalid
def verify(M,P,C,sig,seed=None):
    n = len(P) # ring size

    c0 = sig.c0
    s = sig.s
    I = sig.I
    D = sig.D

    # Reconstruct the aggregation Coefficients
    c = [None]*n
    e1 = hash_to_scalar('MSLRS e1',M,P,C,I,D)
    e2 = hash_to_scalar('MSLRS e2',M,P,C,I,D)

    # Recover signing index if possible
    signer = None
    if seed is not None:
        hashes = 0 # number of hash-constructed scalars found

        for i in range(n):
            if s[i] == hash_to_scalar('MSLRS scalar',seed,I,i):
                hashes += 1
            else:
                signer = i

        # All but one scalar must be hash-constructed
        if hashes != n-1:
            signer = None

    # Signature rounds
    for i in range(0,n):
        if i == 0:
            temp_c = c0
        else:
            temp_c = c[i]
        c[(i+1) % n] = hash_to_scalar('MSLRS round',M,P,C,I,D,s[i]*(G + e1*hash_to_point(P[i])) - temp_c*(P[i] + e1*I + e2*C[i] + e1*e2*D))

    # Final check
    if not c[0] == c0:
        raise ArithmeticError('Verification failed!')
    return signer
