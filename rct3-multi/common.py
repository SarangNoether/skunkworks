# Common constants and such

from dumb25519 import *

# Protocol constants
BITS = 4 # range bit length
RING = 4 # anonymity set size

# Fixed generators
Gc = hash_to_point('Gc') # commitment generator
Hc = hash_to_point('Hc') # commitment generator
U = hash_to_point('U')
G_ip = hash_to_point('G_ip')

# Pedersen commitment
# INPUT
#   a: amount
#   m: mask
def com(a,m):
    return a*Hc + m*Gc

# Determine if a value is a power of 2
#
# INPUTS
#   x: value (int)
# OUTPUTS
#   True if x is a power of 2
def power2(x):
    return x > 0 and (x & (x-1)) == 0
