from dumb25519 import Scalar, ScalarVector, PointVector, random_scalar, hash_to_scalar, hash_to_point, G
from sys import argv

# Helper function for weighted inner product
def wip(a,b,y):
    if not len(a) == len(b):
        raise IndexError('Weighted inner product vectors must have identical size!')
    if not isinstance(a,ScalarVector) or not isinstance(b,ScalarVector):
        raise TypeError('Weighted inner product requires ScalarVectors!')
    if not isinstance(y,Scalar):
        raise TypeError('Weighted inner product requires Scalar weight!')

    r = Scalar(0)
    for i in range(len(a)):
        r += a[i]*y**(i+1)*b[i]
    return r

# Data for a round of the inner product argument
class InnerProductRound:
    def __init__(self,Gi,Hi,G,H,P,a,b,alpha,y):
        # Common data
        self.Gi = Gi
        self.Hi = Hi
        self.G = G
        self.H = H
        self.P = P
        self.y = y
        self.done = False

        # Prover data
        self.a = a
        self.b = b
        self.alpha = alpha

        # Verifier data
        self.A = None
        self.B = None
        self.r1 = None
        self.s1 = None
        self.d1 = None
        self.L = PointVector([])
        self.R = PointVector([])

# Fiat-Shamir transcript hash control
cache = 'pybullet-plus-wip'
def mash(x):
    global cache
    cache = hash_to_scalar(cache,x)

# Perform an inner-product proof round
#
# INPUTS
#   data: round data (InnerProductRound)
def inner_product(data):
    n = len(data.Gi)
    if n == 1:
        data.done = True

        # Random masks
        r = random_scalar()
        s = random_scalar()
        d = random_scalar()
        eta = random_scalar()

        data.A = data.Gi[0]*r + data.Hi[0]*s + data.G*(r*data.y*data.b[0] + s*data.y*data.a[0]) + data.H*d
        data.B = data.G*(r*data.y*s) + data.H*eta

        mash(data.A)
        mash(data.B)
        e = cache

        data.r1 = r + data.a[0]*e
        data.s1 = s + data.b[0]*e
        data.d1 = eta + d*e + data.alpha*e**2

        return

    n /= 2
    a1 = data.a[:n]
    a2 = data.a[n:]
    b1 = data.b[:n]
    b2 = data.b[n:]
    G1 = data.Gi[:n]
    G2 = data.Gi[n:]
    H1 = data.Hi[:n]
    H2 = data.Hi[n:]

    dL = random_scalar()
    dR = random_scalar()

    cL = wip(a1,b2,data.y)
    cR = wip(a2*data.y**n,b1,data.y)
    data.L.append(G2**(a1*data.y.invert()**n) + H1**b2 + data.G*cL + data.H*dL)
    data.R.append(G1**(a2*data.y**n) + H2**b1 + data.G*cR + data.H*dR)

    mash(data.L[-1])
    mash(data.R[-1])
    e = cache

    data.Gi = G1*e.invert() + G2*(e*data.y.invert()**n)
    data.Hi = H1*e +H2*e.invert()

    data.P = data.L[-1]*e**2 + data.P + data.R[-1]*e.invert()**2

    data.a = a1*e + a2*data.y**n*e.invert()
    data.b = b1*e.invert() + b2*e
    data.alpha = dL*e**2 + data.alpha + dR*e.invert()**2

# Run a random prove-verify sequence
def test(N):
    # Curve points and proof quantities
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(N)])
    H = hash_to_point('pybullet H')
    a = ScalarVector([random_scalar() for _ in range(N)])
    b = ScalarVector([random_scalar() for _ in range(N)])
    alpha = random_scalar()
    y = random_scalar()
    P = Gi**a + Hi**b + G*wip(a,b,y) + H*alpha

    mash(y)
    mash(P)

    data = InnerProductRound(Gi,Hi,G,H,P,a,b,alpha,y)
    while True:
        inner_product(data)

        # We have reached the end of the recursion
        if data.done:
            break

    # Complete the verification
    e = cache
    LHS = data.P*e**2 + data.A*e + data.B
    RHS = data.Gi[0]*(data.r1*e) + data.Hi[0]*(data.s1*e) + data.G*(data.r1*data.y*data.s1) + data.H*data.d1
    if not LHS == RHS:
        raise ArithmeticError('Verification failed!')
