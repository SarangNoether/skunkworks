# Schnorr signatures
from dumb25519 import *

# Schnorr signature
class Signature:
    def __init__(self):
        self.c = None
        self.s = None

# Generate a key pair
# OUTPUT
#   x: private key (Scalar)
#   X: public key (Point)
def gen_keys():
    x = random_scalar()
    X = x*G
    return x,X

# Generate a Schnorr signature
#
# INPUT
#   m: message (any hashable data type)
#   x: private key (Scalar)
# OUTPUT
#   sig: Schnorr signature (Signature)
def sign(m,x):
    try:
        hash_to_scalar(m)
    except:
        raise TypeError('Cannot hash message!')

    if not isinstance(x,Scalar):
        raise TypeError('Private key must be a Scalar!')

    # Nonce must be nonzero
    alpha = Scalar(0)
    while alpha == Scalar(0):
        alpha = random_scalar()

    # Construct signature
    sig = Signature()
    sig.c = hash_to_scalar(m, x*G, alpha*G)
    sig.s = alpha - x*sig.c
    return sig

# Verify a Schnorr signature
#
# INPUT
#   m: message (any hashable data type)
#   X: public key (Point)
#   sig: Schnorr signature (Signature)
# OUTPUT
#   True/False: whether the signature is valid
def verify(m,X,sig):
    try:
        hash_to_scalar(m)
    except:
        raise TypeError('Cannot hash message!')

    if not isinstance(X,Point):
        raise TypeError('Public key must be a Point!')

    if not isinstance(sig,Signature):
        raise TypeError('Signature must be a Signature!')
    if not isinstance(sig.c,Scalar) or not isinstance(sig.s,Scalar):
        raise TypeError('Signature components must be Scalars!')

    # Verify the signature
    c = hash_to_scalar(m, X, sig.s*G + sig.c*X)
    return c == sig.c

# Run simple tests
x,X = gen_keys()
m = 'Test message'
assert verify(m,X,sign(m,x)) == True
assert verify('Evil message',X,sign(m,x)) == False
