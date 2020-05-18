# Double-key Schnorr signature

from dumb25519 import *

domain = 'double Schnorr signature' # hash domain separator

class DoubleSchnorr:
    def __init__(self):
        self.c = None
        self.s1 = None
        self.s2 = None

# Generate a double-key signature
# INPUT:
#   m: message
#   p1,P1: first key pair
#   p2,P2: second key pair
# OUTPUT:
#   sig: DoubleSchnorr
def sign(m,p1,P1,p2,P2):
    if not isinstance(p1,Scalar) or not isinstance(P1,Point) or not isinstance(p2,Scalar) or not isinstance(P2,Point):
        raise TypeError('Bad input data type!')
    if not p1*G == P1 or not p2*G == P2:
        raise ValueError('Bad key!')
    try:
        hash_to_scalar(m)
    except:
        raise TypeError('Unable to hash message!')

    k1 = random_scalar()
    k2 = random_scalar()

    sig = DoubleSchnorr()
    sig.c = hash_to_scalar(domain,m,P1,P2,k1*G,k2*G)
    sig.s1 = k1 - p1*sig.c
    sig.s2 = k2 - p2*sig.c
    
    return sig

# Verify a double-key signature
# INPUT:
#   m: message
#   P1,P2: public keys
#   sig: DoubleSchnorr
# OUTPUT:
#   True if valid
#   False if invalid
def verify(m,P1,P2,sig):
    if not isinstance(P1,Point) or not isinstance(P2,Point) or not isinstance(sig,DoubleSchnorr):
        raise TypeError('Bad input data type!')
    try:
        hash_to_scalar(m)
    except:
        raise TypeError('Unable to hash message!')
    if sig.s1 == Scalar(0) or sig.s2 == Scalar(0):
        raise ValueError('Unexpected zero value in signature!')
    
    if hash_to_scalar(domain,m,P1,P2,sig.s1*G + sig.c*P1,sig.s2*G + sig.c*P2) == sig.c:
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
