# Mixed CLSAG: Compressed Linkable Spontaneous Anonymous Group signatures
# https://github.com/monero-project/research-lab/issues/52
#
# For a ring with members of the form (P_i,C_i) such that (P_l,C_l) = (p*G,z*G)
# for some index l, generates a linkable ring signature on a message such that
# any public key is equiprobable as corresponding to the signing key.
#
# Two valid signatures containing the same key image were signed with the same
# private key, regardless of the other ring members used in the signature.
#
# NOTE: The use of this construction in the multi-input case is not advised
# due to the common signing index across inputs.

import dumb25519
from dumb25519 import hash_to_scalar, hash_to_point, random_scalar, G

H = hash_to_point('clsag H')

# CLSAG signature
class Signature:
    h0 = None
    s = None
    I = None

# Generate a CLSAG signature
# INPUTS
#   M: message
#   p: private key vector
#   P: public key vector; rows are ring members, columns are inputs
# RETURNS
#   sig: Signature
# RAISES
#   IndexError if keys are invalid
def sign(M,p,P):
    n = len(P) # ring size
    m = len(P[0]) # inputs

    # Recover the private key index
    if len(p) != m:
        raise IndexError('Incorrect number of private keys!')
    l = None # private index
    for i in range(n):
        if P[i][0] == G*p[0]:
            l = i
    if l is not None:
        for j in range(m):
            if P[l][j] != G*p[j]:
                raise IndexError('Bad private key!')
    else:
        raise IndexError('Bad private key!')

    # Construct key images
    I = []
    for j in range(m):
        I.append(H*p[j])

    # Now generate the signature
    mu = []
    for j in range(m):
        mu.append(hash_to_scalar(j,P,I))
    h = [None]*n
    alpha = random_scalar()
    s = [random_scalar()]*n

    # Private index
    L = G*alpha
    R = H*alpha
    h[(l+1) % n] = hash_to_scalar(P,M,L,R)
   
    # Decoy indices
    if n > 1:
        for i in range(l+1,l+n):
            i = i % n
            L = G*s[i]
            R = H*s[i]
            for j in range(m):
                L += P[i][j]*(h[i]*mu[j])
                R += I[j]*(h[i]*mu[j])
            h[(i+1) % n] = hash_to_scalar(P,M,L,R)

    # Final scalar computation
    s[l] = alpha
    for j in range(m):
        s[l] -= p[j]*h[l]*mu[j]

    # Assemble the signature
    sig = Signature()
    sig.h0 = h[0]
    sig.s = s
    sig.I = I

    return sig

# Verify a CLSAG signature
# INPUTS
#   M: message
#   P: public key vector
#   sig: Signature
# RETURNS
#   True if signature is valid
# RAISES
#   ArithmeticError if signature is invalid
def verify(M,P,sig):
    n = len(P) # ring size
    m = len(P[0]) # inputs

    h0 = sig.h0
    s = sig.s
    I = sig.I

    # Reconstruct the commitments
    h = [None]*n
    mu = []
    for j in range(m):
        mu.append(hash_to_scalar(j,P,I))

    for i in range(0,n):
        if i == 0:
            temp_h = h0
        else:
            temp_h = h[i]
        L = G*s[i%n]
        R = H*s[i%n]
        for j in range(m):
            L += P[i%n][j]*(temp_h*mu[j])
            R += I[j]*(temp_h*mu[j])
        h[(i+1)%n] = hash_to_scalar(P,M,L,R)

    # Final check
    if not h[0] == h0:
        raise ArithmeticError('Verification failed!')
    return True
