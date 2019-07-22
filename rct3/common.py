# Common constants and such

from dumb25519 import *

# Protocol constants
BITS = 4 # range bit length
RING = 4 # anonymity set size

# Fixed generators
H = hash_to_point('H')
Gc = hash_to_point('Gc') # commitment generator
Hc = hash_to_point('Hc') # commitment generator
U = hash_to_point('U')
G0 = hash_to_point('G0')
Hi = []
for i in range(RING):
    Hi.append(hash_to_point('Hi',i))

# Pedersen commitment
# INPUT
#   v: value
#   a: mask
def com(v,a):
    return v*Hc + a*Gc
