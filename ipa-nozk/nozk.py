from dumb25519 import Scalar, ScalarVector, PointVector, random_scalar, hash_to_scalar, hash_to_point, multiexp, Z
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
        self.L = PointVector([])
        self.R = PointVector([])

        # Challenges
        self.x = ScalarVector([])

# Fiat-Shamir transcript hash control
cache = ''
def mash(x):
    global cache
    cache = hash_to_scalar(cache,x)

# Perform an inner-product proof round
#
# INPUTS
#   data: round data (InnerProductRound)
def inner_product(data):
    n = len(data.G)
    if n == 1:
        data.done = True
        return

    n /= 2
    cL = data.a[:n]**data.b[n:]
    cR = data.a[n:]**data.b[:n]
    data.L.append(data.G[n:]*data.a[:n] + data.H[:n]*data.b[n:] + data.U*cL)
    data.R.append(data.G[:n]*data.a[n:] + data.H[n:]*data.b[:n] + data.U*cR)

    mash(data.L[-1])
    mash(data.R[-1])
    x = cache
    data.x.append(x)
    
    data.G = data.G[:n] + data.G[n:]*x
    data.H = data.H[:n]*x + data.H[n:]

    data.P = x**2*data.L[-1] + x*data.P + data.R[-1]

    data.a = data.a[:n]*x + data.a[n:]
    data.b = data.b[:n] + data.b[n:]*x

def test(a,b,N):
    # The unrolled recursion applies only to N > 1
    if not N > 1:
        raise ValueError('Bit length is too small!')

    # Curve points and proof quantities
    Gi = PointVector([hash_to_point('Gi ' + str(i)) for i in range(N)])
    Hi = PointVector([hash_to_point('Hi ' + str(i)) for i in range(N)])
    U = hash_to_point('U')

    # The compound commitment
    t = a**b
    P = Gi*a + Hi*b + U*t
    mash(P)
    mash(t)

    # Point offset
    alpha = cache
    U = U*alpha.invert()

    #
    # Generate the inner product proof
    #
    data = InnerProductRound(Gi,Hi,U,a,b,P-(alpha-Scalar(1))*t*U)
    while True:
        inner_product(data)

        # We have reached the end of the recursion
        if data.done:
            break

    # Silly verification, with the recursion all rolled up
    if not data.P == data.G[0]*data.a[0] + data.H[0]*data.b[0] + U*(data.a[0]*data.b[0]):
        raise ArithmeticError('Rolled recursion failure!')

    #
    # Now perform verification, with the recursion unrolled for efficiency
    #

    # Update Gi/Hi scalars
    scalars = ScalarVector([])
    points = PointVector([])
    bits = len(data.x)
    for x in range(N):
        g = data.a[0]
        h = data.b[0]
        i = 1
        j = 0
        while i < N:
            if i & x:
                g *= data.x[bits-j-1]
            else:
                h *= data.x[bits-j-1]
            i <<= 1
            j += 1
        scalars.append(g)
        points.append(Gi[x])
        scalars.append(h)
        points.append(Hi[x])

    # Update L/R/P scalars
    p = Scalar(1)
    for i in range(len(data.x)):
        l = -data.x[i]**2
        r = Scalar(-1)
        for j in range(i+1,len(data.x)):
            l *= data.x[j]
            r *= data.x[j]
        scalars.append(l)
        points.append(data.L[i])
        scalars.append(r)
        points.append(data.R[i])
        p *= data.x[i]

    # Note the verifier must use an offset P here
    scalars.append(-p)
    points.append(P - (alpha-Scalar(1))*t*U)

    scalars.append(data.a[0]*data.b[0])
    points.append(U)

    if not multiexp(scalars,points) == Z:
        raise ArithmeticError('Unrolled verification failed!')
