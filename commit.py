# Pedersen commitments and algebra
from dumb25519 import *
import schnorr

H = hash_to_point('H')

# Construct a Pedersen commitment
#
# INPUT
#   v: value (Scalar)
#   r: mask (Scalar)
# OUTPUT
#   C: commitment (Point)
def commit(v,r):
    return r*G + v*H

# Generate a Schnorr signature on the difference of two commitments
# This shows the prover knows the discrete log of this difference,
#   and therefore that the commitments are to the same value
v = random_scalar() # common value
r = random_scalar() # masks
s = random_scalar()

C = commit(v,r) # commitments
D = commit(v,s)

m = hash_to_scalar(C,D) # message is the public information

# Generate a valid signature
sig = schnorr.sign(m,r-s)
assert schnorr.verify(m,C-D,sig) == True

# Gnerate an invalid signature
E = commit(random_scalar(),s)
m = hash_to_scalar(C,E)
sig = schnorr.sign(m,r-s)
assert schnorr.verify(m,C-E,sig) == False
