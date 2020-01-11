import dumb25519
from dumb25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point
from common import *
import transcript

inv8 = Scalar(8).invert()

# Proof structure
class Bulletproof:
    def __init__(self,V,A,S,T1,T2,taux,mu,L,R,a,b,t):
        self.V = V
        self.A = A
        self.S = S
        self.T1 = T1
        self.T2 = T2
        self.taux = taux
        self.mu = mu
        self.L = L
        self.R = R
        self.a = a
        self.b = b
        self.t = t

# Data for a round of the inner product argument
class InnerProductRound:
    def __init__(self,G,H,U,a,b,tr):
        # Common data
        self.G = G
        self.H = H
        self.U = U
        self.done = False

        # Prover data
        self.a = a
        self.b = b

        # Verifier data (appended lists)
        self.L = PointVector([])
        self.R = PointVector([])

        # Transcript
        self.tr = tr

# Turn a scalar into a vector of bit scalars
#
# INPUTS
#   s: (Scalar)
#   N: number of bits (int)
# OUTPUTS
#   ScalarVector
def scalar_to_bits(s,N):
    result = []
    for i in range(N-1,-1,-1):
        if s/Scalar(2**i) == Scalar(0):
            result.append(Scalar(0))
        else:
            result.append(Scalar(1))
            s -= Scalar(2**i)
    return ScalarVector(list(reversed(result)))

# Generate a vector of powers of a scalar
#
# INPUTS
#   s: (Scalar)
#   l: number of powers to include (int)
# OUTPUTS
#   ScalarVector
def exp_scalar(s,l):
    return ScalarVector([s**i for i in range(l)])

# Sum the powers of a scalar
#
# INPUTS
#   s: (Scalar)
#   l: number of powers to include (int)
# OUTPUTS
#   s^0+s^1+...+s^(l-1) (Scalar)
def sum_scalar(s,l):
    if not l & (l-1) == 0:
        raise ValueError('We need l to be a power of 2!')

    if l == 0:
        return Scalar(0)
    if l == 1:
        return Scalar(1)

    r = Scalar(1) + s
    while l > 2:
        s = s*s
        r += s*r
        l /= 2
    return r

# Perform an inner-product proof round
#
# INPUTS
#   data: round data (InnerProductRound)
def inner_product(data):
    n = len(data.G)
    if n == 1:
        data.done = True
        data.a = data.a[0]
        data.b = data.b[0]
        return

    n /= 2
    cL = data.a[:n]**data.b[n:]
    cR = data.a[n:]**data.b[:n]
    data.L.append((data.G[n:]**data.a[:n] + data.H[:n]**data.b[n:] + data.U*cL)*inv8)
    data.R.append((data.G[:n]**data.a[n:] + data.H[n:]**data.b[:n] + data.U*cR)*inv8)

    data.tr.update(data.L[-1])
    data.tr.update(data.R[-1])
    x = data.tr.challenge()

    data.G = data.G[:n]*x.invert() + data.G[n:]*x
    data.H = data.H[:n]*x + data.H[n:]*x.invert()

    data.a = data.a[:n]*x + data.a[n:]*x.invert()
    data.b = data.b[:n]*x.invert() + data.b[n:]*x

# Generate a multi-output proof
#
# INPUTS
#   data: list of value/mask pairs (Scalars)
#   N: number of bits in range (int)
# OUTPUTS
#   Bulletproof
def prove(data,N):
    tr = transcript.Transcript('Bulletproof')
    M = len(data)

    # curve points
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(M*N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(M*N)])

    # set amount commitments
    V = PointVector([])
    aL = ScalarVector([])
    for v,gamma in data:
        V.append(com(v,gamma)*inv8)
        tr.update(V[-1])
        aL.extend(scalar_to_bits(v,N))

    # set bit arrays
    aR = ScalarVector([])
    for bit in aL.scalars:
        aR.append(bit-Scalar(1))

    alpha = random_scalar()
    A = (Gi**aL + Hi**aR + Gc*alpha)*inv8

    sL = ScalarVector([random_scalar()]*(M*N))
    sR = ScalarVector([random_scalar()]*(M*N))
    rho = random_scalar()
    S = (Gi**sL + Hi**sR + Gc*rho)*inv8

    # get challenges
    tr.update(A)
    tr.update(S)
    y = tr.challenge()
    z = tr.challenge()
    y_inv = y.invert()

    # polynomial coefficients
    l0 = aL - ScalarVector([z]*(M*N))
    l1 = sL

    # for polynomial coefficients
    zeros_twos = []
    z_cache = z**2
    for j in range(M):
        for i in range(N):
            zeros_twos.append(z_cache*2**i)
        z_cache *= z
    
    # more polynomial coefficients
    r0 = aR + ScalarVector([z]*(M*N))
    r0 = r0*exp_scalar(y,M*N)
    r0 += ScalarVector(zeros_twos)
    r1 = exp_scalar(y,M*N)*sR

    # build the polynomials
    t0 = l0**r0
    t1 = l0**r1 + l1**r0
    t2 = l1**r1

    tau1 = random_scalar()
    tau2 = random_scalar()
    T1 = com(t1,tau1)*inv8
    T2 = com(t2,tau2)*inv8

    tr.update(T1)
    tr.update(T2)
    x = tr.challenge()

    taux = tau1*x + tau2*(x**2)
    for j in range(1,M+1):
        gamma = data[j-1][1]
        taux += z**(1+j)*gamma
    mu = x*rho+alpha
    
    l = l0 + l1*x
    r = r0 + r1*x
    t = l**r

    tr.update(taux)
    tr.update(mu)
    tr.update(t)
    x_ip = tr.challenge()

    # initial inner product inputs
    data = InnerProductRound(Gi,PointVector([Hi[i]*(y_inv**i) for i in range(len(Hi))]),Hc*x_ip,l,r,tr)
    while True:
        inner_product(data)

        # we have reached the end of the recursion
        if data.done:
            return Bulletproof(V,A,S,T1,T2,taux,mu,data.L,data.R,data.a,data.b,t)

# Verify a batch of multi-output proofs
#
# INPUTS
#   proofs: list of proofs (Bulletproofs)
#   N: number of bits in range (int)
# OUTPUTS
#   True if all proofs are valid
def verify(proofs,N):
    # determine the length of the longest proof
    max_MN = 2**max([len(proof.L) for proof in proofs])

    # curve points
    Z = dumb25519.Z
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(max_MN)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(max_MN)])

    # set up weighted aggregates
    y0 = Scalar(0)
    y1 = Scalar(0)
    z1 = Scalar(0)
    z3 = Scalar(0)
    z4 = [Scalar(0)]*max_MN
    z5 = [Scalar(0)]*max_MN
    scalars = ScalarVector([]) # for final check
    points = PointVector([]) # for final check

    # run through each proof
    for proof in proofs:
        tr = transcript.Transcript('Bulletproof')

        V = proof.V
        A = proof.A
        S = proof.S
        T1 = proof.T1
        T2 = proof.T2
        taux = proof.taux
        mu = proof.mu
        L = proof.L
        R = proof.R
        a = proof.a
        b = proof.b
        t = proof.t

        # get size information
        M = 2**len(L)/N

        # weighting factors for batching
        weight_y = random_scalar()
        weight_z = random_scalar()
        if weight_y == Scalar(0) or weight_z == Scalar(0):
            raise ArithmeticError

        # reconstruct challenges
        for v in V:
            tr.update(v)
        tr.update(A)
        tr.update(S)
        y = tr.challenge()
        if y == Scalar(0):
            raise ArithmeticError
        y_inv = y.invert()
        z = tr.challenge()
        if z == Scalar(0):
            raise ArithmeticError
        tr.update(T1)
        tr.update(T2)
        x = tr.challenge()
        if x == Scalar(0):
            raise ArithmeticError
        tr.update(taux)
        tr.update(mu)
        tr.update(t)
        x_ip = tr.challenge()
        if x_ip == Scalar(0):
            raise ArithmeticError

        y0 += taux*weight_y
        
        k = (z-z**2)*sum_scalar(y,M*N)
        for j in range(1,M+1):
            k -= (z**(j+2))*sum_scalar(Scalar(2),N)

        y1 += (t-k)*weight_y

        for j in range(M):
            scalars.append(z**(j+2)*weight_y)
            points.append(V[j]*Scalar(8))
        scalars.append(x*weight_y)
        points.append(T1*Scalar(8))
        scalars.append(x**2*weight_y)
        points.append(T2*Scalar(8))

        scalars.append(weight_z)
        points.append(A*Scalar(8))
        scalars.append(x*weight_z)
        points.append(S*Scalar(8))

        # inner product
        W = ScalarVector([])
        for i in range(len(L)):
            tr.update(L[i])
            tr.update(R[i])
            W.append(tr.challenge())
            if W[i] == Scalar(0):
                raise ArithmeticError
        W_inv = W.invert()

        for i in range(M*N):
            index = i
            g = a
            h = b*((y_inv)**i)
            for j in range(len(L)-1,-1,-1):
                J = len(W)-j-1
                base_power = 2**j
                if index/base_power == 0:
                    g *= W_inv[J]
                    h *= W[J]
                else:
                    g *= W[J]
                    h *= W_inv[J]
                    index -= base_power

            g += z
            h -= (z*(y**i) + (z**(2+i/N))*(Scalar(2)**(i%N)))*((y_inv)**i)

            z4[i] += g*weight_z
            z5[i] += h*weight_z

        z1 += mu*weight_z

        for i in range(len(L)):
            scalars.append(W[i]**2*weight_z)
            points.append(L[i]*Scalar(8))
            scalars.append(W_inv[i]**2*weight_z)
            points.append(R[i]*Scalar(8))
        z3 += (t-a*b)*x_ip*weight_z
    
    # now check all proofs together
    scalars.append(-y0-z1)
    points.append(Gc)
    scalars.append(-y1+z3)
    points.append(Hc)
    for i in range(max_MN):
        scalars.append(-z4[i])
        points.append(Gi[i])
        scalars.append(-z5[i])
        points.append(Hi[i])

    if not dumb25519.multiexp(scalars,points) == Z:
        raise ArithmeticError('Bad verification!')

    return True
