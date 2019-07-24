from dumb25519 import ScalarVector, PointVector, random_scalar, hash_to_scalar, hash_to_point
from sys import argv

# Data for a round of the inner product argument
class InnerProductRound:
    def __init__(self,G,H,U,a,b,P):
        # Common data
        self.G = G
        self.H = H
        self.U = U
        self.P = P
        self.done = False

        # Prover data
        self.a = a
        self.b = b

        # Verifier data (appended lists)
        self.aa = ScalarVector([])
        self.bb = ScalarVector([])
        self.L = PointVector([])
        self.R = PointVector([])

# Fiat-Shamir transcript hash control
cache = ''
def mash(x):
    global cache
    cache = hash_to_scalar(cache,x)

# Decompose a value into bits
def decomp(val,size):
    r = []
    for i in range(size-1,-1,-1):
        slot = 2**i
        r.append(int(val/slot))
        val -= slot*r[-1]
    r = list(reversed(r))

    return r

# Perform an inner-product proof round
#
# INPUTS
#   data: round data (InnerProductRound)
def inner_product(data):
    n = len(data.G)
    if n == 1:
        data.done = True
        return
    if (n % 2) == 1:
        n -= 1
        data.aa.append(data.a[-1])
        data.bb.append(data.b[-1])
        data.P = data.P - data.G[-1]*data.a[-1] - data.H[-1]*data.b[-1] - data.U*(data.a[-1]*data.b[-1])
        data.G = data.G[:-1]
        data.H = data.H[:-1]
        data.a = data.a[:-1]
        data.b = data.b[:-1]

    n /= 2
    cL = data.a[:n]**data.b[n:]
    cR = data.a[n:]**data.b[:n]
    data.L.append(data.G[n:]*data.a[:n] + data.H[:n]*data.b[n:] + data.U*cL)
    data.R.append(data.G[:n]*data.a[n:] + data.H[n:]*data.b[:n] + data.U*cR)

    mash(data.L[-1])
    mash(data.R[-1])
    x = cache

    data.G = (data.G[:n]*x.invert())*(data.G[n:]*x)
    data.H = (data.H[:n]*x)*(data.H[n:]*x.invert())

    data.P = data.L[-1]*x**2 + data.P + data.R[-1]*x.invert()**2

    data.a = data.a[:n]*x + data.a[n:]*x.invert()
    data.b = data.b[:n]*x.invert() + data.b[n:]*x

def test(a,b,N):
    # Curve points and proof quantities
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(N)])
    U = hash_to_point('pybullet U')
    P = Gi*a + Hi*b + U*(a**b)

    data = InnerProductRound(Gi,Hi,U,a,b,P)
    while True:
        inner_product(data)

        # We have reached the end of the recursion
        if data.done:
            break

    # Complete the verification
    c = data.a[0]*data.b[0]
    if not data.P == data.G[0]*data.a[0] + data.H[0]*data.b[0] + data.U*c:
        raise ArithmeticError('Verification failed!')
