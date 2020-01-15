# CLSAG: Compressed Linkable Spontaneous Anonymous Group signatures
# https://github.com/monero-project/research-lab/issues/52
#
# For a ring with members of the form (P_i,C_i,T_i) such that (P_l,C_l,T_l) = (p*G,z*G,w*G)
# for some index l, generates a linkable ring signature on a message such that
# any public key is equiprobable as corresponding to the signing key.
#
# Two valid signatures containing the same key image were signed with the same
# private key, regardless of the other ring members used in the signature.
#
# This version is designed to support hidden timelocks.

import dumb25519
from dumb25519 import hash_to_scalar, hash_to_point, random_scalar, G

# CLSAG signature
class Signature:
    h0 = None
    s = None
    I = None
    D = None # auxiliary tag (amount commitments)
    E = None # auxiliary tag (timelock commitments)

# Generate a CLSAG signature
# INPUTS
#   M: message
#   p: private key
#   P: public key vector
#   z: commitment private key
#   C: commitment vector
#   w: timelock private key
#   T: timelock vector
#   index: if set, bypass key index check (testing only)
# RETURNS
#   sig: Signature
# RAISES
#   IndexError if index is not set and private keys are invalid
def sign(M,p,P,z,C,w,T,index=None):
    n = len(P) # ring size

    # Recover the private key index
    l = None
    if index is not None:
        l = index
    else:
        for i in range(n):
            if P[i] == G*p and C[i] == G*z and T[i] == G*w:
                l = i
                break
        if l is None:
            raise IndexError('Private keys must correspond to public keys!')

    # Construct key images
    I = hash_to_point(P[l])*p
    D = hash_to_point(P[l])*z
    E = hash_to_point(P[l])*w

    # Now generate the signature
    mu_P = hash_to_scalar(0,P,I,C,D,T,E)
    mu_C = hash_to_scalar(1,P,I,C,D,T,E)
    mu_T = hash_to_scalar(2,P,I,C,D,T,E)

    h = [None]*n
    alpha = random_scalar()
    s = [random_scalar()]*n

    # Private index
    L = G*alpha
    R = hash_to_point(P[l])*alpha
    h[(l+1) % n] = hash_to_scalar(P,C,T,M,L,R)
   
    # Decoy indices
    if n > 1:
        for i in range(l+1,l+n):
            i = i % n
            L = G*s[i] + P[i]*(h[i]*mu_P) + C[i]*(h[i]*mu_C) + T[i]*(h[i]*mu_T)
            R = hash_to_point(P[i])*s[i] + I*(h[i]*mu_P) + D*(h[i]*mu_C) + E*(h[i]*mu_T)
            h[(i+1) % n] = hash_to_scalar(P,C,T,M,L,R)

    # Final scalar computation
    s[l] = alpha - h[l]*(mu_P*p + mu_C*z + mu_T*w)

    # Assemble the signature
    sig = Signature()
    sig.h0 = h[0]
    sig.s = s
    sig.I = I
    sig.D = D
    sig.E = E

    return sig

# Verify a CLSAG signature
# INPUTS
#   M: message
#   P: public key vector
#   C: commitment vector
#   T: timelock vector
#   sig: Signature
# RETURNS
#   True if signature is valid
# RAISES
#   ArithmeticError if signature is invalid
def verify(M,P,C,T,sig):
    n = len(P) # ring size

    h0 = sig.h0
    s = sig.s
    I = sig.I
    D = sig.D
    E = sig.E

    # Reconstruct the commitments
    h = [None]*n
    mu_P = hash_to_scalar(0,P,I,C,D,T,E)
    mu_C = hash_to_scalar(1,P,I,C,D,T,E)
    mu_T = hash_to_scalar(2,P,I,C,D,T,E)

    for i in range(0,n):
        if i == 0:
            temp_h = h0
        else:
            temp_h = h[i]
        L = G*s[i%n] + P[i%n]*(temp_h*mu_P) + C[i%n]*(temp_h*mu_C) + T[i%n]*(temp_h*mu_T)
        R = hash_to_point(P[i%n])*s[i%n] + I*(temp_h*mu_P) + D*(temp_h*mu_C) + E*(temp_h*mu_T)
        h[(i+1)%n] = hash_to_scalar(P,C,T,M,L,R)

    # Final check
    if not h[0] == h0:
        raise ArithmeticError('Verification failed!')
    return True
