# Mixed CLSAG: Compressed Linkable Spontaneous Anonymous Group signatures
# https://github.com/monero-project/research-lab/issues/52
#
# For a ring with members of the form (P_i,C_i) such that (P_l,C_l) = (p*G,z*G)
# for some index l, generates a linkable ring signature on a message such that
# any public key is equiprobable as corresponding to the signing key.
#
# Two valid signatures containing the same key image were signed with the same
# private key, regardless of the other ring members used in the signature.

import dumb25519
from dumb25519 import hash_to_scalar, hash_to_point, random_scalar, G

# Constants
TYPE_LEGACY = 0
TYPE_NEW = 1
H = hash_to_point('clsag H')

# CLSAG signature
class Signature:
    h0 = None
    s = None
    I = None
    D = None

# Generate a CLSAG signature
# INPUTS
#   M: message
#   p: private key
#   P: public key vector
#   t: key type vector
#   z: commitment private key
#   C: commitment vector
#   index: if set, bypass key index check (testing only)
# RETURNS
#   sig: Signature
# RAISES
#   IndexError if index is not set and private keys are invalid
def sign(M,p,P,t,z,C,index=None):
    n = len(P) # ring size

    # Recover the private key index
    l = None
    if index is not None:
        l = index
    else:
        for i in range(n):
            if P[i] == G*p and C[i] == G*z:
                l = i
                break
        if l is None:
            raise IndexError('Private keys must correspond to public keys!')

    # Construct key images
    if t[l] == TYPE_LEGACY:
        I = hash_to_point(P[l])*p
        D = hash_to_point(P[l])*z
    else:
        I = H*p
        D = H*z

    # Now generate the signature
    mu_P = hash_to_scalar(0,P,I,C,D)
    mu_C = hash_to_scalar(1,P,I,C,D)
    h = [None]*n
    alpha = random_scalar()
    s = [random_scalar()]*n

    # Private index
    L = G*alpha
    if t[l] == TYPE_LEGACY:
        R = hash_to_point(P[l])*alpha
    else:
        R = H*alpha
    h[(l+1) % n] = hash_to_scalar(L,R)
   
    # Decoy indices
    if n > 1:
        for i in range(l+1,l+n):
            i = i % n
            L = G*s[i] + h[i]*(P[i]*mu_P + C[i]*mu_C)
            if t[i] == TYPE_LEGACY:
                R = hash_to_point(P[i])*s[i] + h[i]*(I*mu_P + D*mu_C)
            else:
                R = H*s[i] + h[i]*(I*mu_P + D*mu_C)
            h[(i+1) % n] = hash_to_scalar(L,R)

    # Final scalar computation
    s[l] = alpha - h[l]*(mu_P*p + mu_C*z)

    # Assemble the signature
    sig = Signature()
    sig.h0 = h[0]
    sig.s = s
    sig.I = I
    sig.D = D

    return sig

# Verify a CLSAG signature
# INPUTS
#   M: message
#   P: public key vector
#   t: key type vector
#   C: commitment vector
#   sig: Signature
# RETURNS
#   True if signature is valid
# RAISES
#   ArithmeticError if signature is invalid
def verify(M,P,t,C,sig):
    n = len(P) # ring size

    h0 = sig.h0
    s = sig.s
    I = sig.I
    D = sig.D

    # Reconstruct the commitments
    h = [None]*n
    mu_P = hash_to_scalar(0,P,I,C,D)
    mu_C = hash_to_scalar(1,P,I,C,D)

    for i in range(0,n):
        if i == 0:
            temp_h = h0
        else:
            temp_h = h[i]
        L = G*s[i%n] + temp_h*(P[i%n]*mu_P + C[i%n]*mu_C)
        if t[i] == TYPE_LEGACY:
            R = hash_to_point(P[i%n])*s[i%n] + temp_h*(I*mu_P + D*mu_C)
        else:
            R = H*s[i%n] + temp_h*(I*mu_P + D*mu_C)
        h[(i+1)%n] = hash_to_scalar(L,R)

    # Final check
    if not h[0] == h0:
        raise ArithmeticError('Verification failed!')
    return True
