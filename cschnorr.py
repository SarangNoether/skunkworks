# Double-key compact Schnorr signature

from dumb25519 import *

domain = 'double compact Schnorr signature' # hash domain separator
domain_aggregate = 'double compact Schnorr signature aggregator' # key aggregator separator

class DoubleCompactSchnorr:
    def __init__(self):
        self.c = None
        self.s = None

# Generate a double-key compact signature
# INPUT:
#   m: message
#   p1,P1: first key pair
#   p2,P2: second key pair
# OUTPUT:
#   sig: DoubleCompactSchnorr
def sign(m,p1,P1,p2,P2):
    if not isinstance(p1,Scalar) or not isinstance(P1,Point) or not isinstance(p2,Scalar) or not isinstance(P2,Point):
        raise TypeError('Bad input data type!')
    if not p1*G == P1 or not p2*G == P2:
        raise ValueError('Bad key!')
    try:
        hash_to_scalar(m)
    except:
        raise TypeError('Unable to hash message!')

    k = random_scalar()
    mu = hash_to_scalar(domain_aggregate,m,P1,P2)

    sig = DoubleCompactSchnorr()
    sig.c = hash_to_scalar(domain,m,P1,P2,k*G)
    sig.s = k - (p1 + mu*p2)*sig.c
    
    return sig

# Verify a double-key compact signature
# INPUT:
#   m: message
#   P1,P2: public keys
#   sig: DoubleCompactSchnorr
# OUTPUT:
#   True if valid
#   False if invalid
def verify(m,P1,P2,sig):
    if not isinstance(P1,Point) or not isinstance(P2,Point) or not isinstance(sig,DoubleCompactSchnorr):
        raise TypeError('Bad input data type!')
    try:
        hash_to_scalar(m)
    except:
        raise TypeError('Unable to hash message!')
    if sig.s == Scalar(0):
        raise ValueError('Unexpected zero value in signature!')
    
    mu = hash_to_scalar(domain_aggregate,m,P1,P2)
    if hash_to_scalar(domain,m,P1,P2,sig.s*G + sig.c*(P1 + mu*P2)) == sig.c:
        return True
    return False

# Run a random test
print 'Running random test...'
p1 = random_scalar()
P1 = p1*G
p2 = random_scalar()
P2 = p2*G
m = random_scalar() # or any hashable data type

if not verify(m,P1,P2,sign(m,p1,P1,p2,P2)):
    raise ArithmeticError('Bad signature test!')
print 'Done!'
