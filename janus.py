# Simulation of Janus attack and mitigation
#
# NOTE: for research only; do not deploy

from dumb25519 import *

# Master wallet address
a = random_scalar()
A = a*G # view key
b = random_scalar()
B = b*G # spend key

# Subaddresses with indices 0 and 1 (arbitrary)
b_0 = hash_to_scalar(a,0) + b
B_0 = b_0*G
a_0 = a*b_0
A_0 = a_0*G

b_1 = hash_to_scalar(a,1) + b
B_1 = b_1*G
a_1 = a*b_1
A_1 = a_1*G

# Generate a Janus output
print 'Beginning a Janus attack...'
print 'Transaction key indicates index 0'
r = random_scalar() # transaction private key
R = r*B_0
P = hash_to_scalar(r*A_0)*G + B_1 # NOTE: index mismatch!

# Recover the output private key
B_x = P - hash_to_scalar(a*R)*G
if B_x == B_1:
    print 'Recipient sees index 1; attack succeeded!'
else:
    raise IndexError('Janus attack was not successful!')

# Mitigate the attack by including second transaction key
print 'Including Janus mitigation...'
R1 = r*G

# Test the Janus output against the mitigation
if not R - b_1*R1 == Z:
    print 'Mitigation detected attack!'
else:
    raise ValueError('Mitigation failed to detect attack!')
