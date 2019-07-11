# Common constants and such

import dumb25519

# Fixed generators
G = dumb25519.G
H = dumb25519.hash_to_point('H')

# Range bit length
BITS = 4

# Pedersen commitment
# INPUT
#   v: value
#   a: mask
def com(v,a):
    return v*H + a*G
