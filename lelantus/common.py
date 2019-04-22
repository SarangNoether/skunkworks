# Common constants and such

import dumb25519

# Fixed generators
G = dumb25519.G
H = dumb25519.hash_to_point('H')
H1 = dumb25519.hash_to_point('H1')
H2 = dumb25519.hash_to_point('H2')

# Range bit length
BITS = 4
