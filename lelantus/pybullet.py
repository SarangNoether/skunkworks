from common import *
from dumb25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point

cache = '' # rolling transcript hash
inv8 = Scalar(8).invert()

# Proof structure
class Bulletproof:
    V = None
    A = None
    S = None
    T1 = None
    T2 = None
    taux1 = None
    taux2 = None
    mu = None
    L = None
    R = None
    a = None
    b = None
    t = None

# Add to a transcript hash
def mash(s):
    global cache
    cache = hash_to_scalar(cache,s)

# Clear the transcript hash
def clear_cache():
    global cache
    cache = ''

# Turn a scalar into a vector of bit scalars
# s: Scalar
# N: int; number of bits
#
# returns: ScalarVector
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
# s: Scalar
# l: int; number of powers to include
#
# returns: ScalarVector
def exp_scalar(s,l):
    return ScalarVector([s**i for i in range(l)])

# Sum the powers of a scalar
# s: Scalar
# l: int; number of powers to include
#
# returns: Scalar; s^0+s^1+...+s^(l-1)
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
# G,H: PointVector
# U: Point
# a,b: ScalarVector
#
# returns: G',H',U,a',b',L,R
def inner_product(data):
    G,H,U,a,b,L,R = data

    n = len(G)
    if n == 1:
        return [a[0],b[0]]

    n /= 2
    cL = a[:n]**b[n:]
    cR = a[n:]**b[:n]
    L = (G[n:]*a[:n] + H[:n]*b[n:] + U*cL)*inv8
    R = (G[:n]*a[n:] + H[n:]*b[:n] + U*cR)*inv8

    mash(L)
    mash(R)
    x = cache

    G = (G[:n]*x.invert())*(G[n:]*x)
    H = (H[:n]*x)*(H[n:]*x.invert())

    a = a[:n]*x + a[n:]*x.invert()
    b = b[:n]*x.invert() + b[n:]*x
    
    return [G,H,U,a,b,L,R]

# Generate a multi-output proof
# data: [s,v,r] commitment data; [Scalar,Scalar,Scalar] triplets
# N: number of bits in range
#
# returns: list of proof data
def prove(data,N):
    clear_cache()
    M = len(data)

    # curve points
    Gi = PointVector([hash_to_point('Gi ' + str(i)) for i in range(M*N)])
    Hi = PointVector([hash_to_point('Hi ' + str(i)) for i in range(M*N)])

    # set amount commitments
    # [s,v,r] -> s*G + v*H1 + r*H2
    V = PointVector([])
    aL = ScalarVector([])
    for s,v,r in data: # s,v,r
        V.append((G*s + H1*v + H2*r)*inv8)
        mash(V[-1])
        aL.extend(scalar_to_bits(v,N))

    # set bit arrays
    aR = ScalarVector([])
    for bit in aL.scalars:
        aR.append(bit-Scalar(1))

    alpha = random_scalar()
    A = (Gi*aL + Hi*aR + G*alpha)*inv8

    sL = ScalarVector([random_scalar()]*(M*N))
    sR = ScalarVector([random_scalar()]*(M*N))
    rho = random_scalar()
    S = (Gi*sL + Hi*sR + G*rho)*inv8

    # get challenges
    mash(A)
    mash(S)
    y = cache
    y_inv = y.invert()
    mash('')
    z = cache

    # polynomial coefficients
    l0 = aL - ScalarVector([z]*(M*N))
    l1 = sL

    # ugly sum
    zeros_twos = []
    for i in range (M*N):
        zeros_twos.append(Scalar(0))
        for j in range(1,M+1):
            temp = Scalar(0)
            if i >= (j-1)*N and i < j*N:
                temp = Scalar(2)**(i-(j-1)*N)
            zeros_twos[-1] += temp*(z**(1+j))
    
    # more polynomial coefficients
    r0 = aR + ScalarVector([z]*(M*N))
    r0 = r0*exp_scalar(y,M*N)
    r0 += ScalarVector(zeros_twos)
    r1 = exp_scalar(y,M*N)*sR

    # build the polynomials
    t0 = l0**r0
    t1 = l0**r1 + l1**r0
    t2 = l1**r1

    tau11 = random_scalar()
    tau21 = random_scalar()
    tau12 = random_scalar()
    tau22 = random_scalar()
    T1 = (H1*t1 + G*tau11 + H2*tau21)*inv8
    T2 = (H1*t2 + G*tau12 + H2*tau22)*inv8

    mash(T1)
    mash(T2)
    x = cache # challenge

    taux1 = tau12*(x**2) + tau11*x
    taux2 = tau22*(x**2) + tau21*x
    for j in range(1,M+1):
        s = data[j-1][0]
        r = data[j-1][2]
        taux1 += z**(1+j)*s
        taux2 += z**(1+j)*r
    mu = x*rho+alpha
    
    l = l0 + l1*x
    r = r0 + r1*x
    t = l**r

    mash(taux1)
    mash(taux2)
    mash(mu)
    mash(t)

    x_ip = cache # challenge
    L = PointVector([])
    R = PointVector([])
   
    # initial inner product inputs
    data_ip = [Gi,PointVector([Hi[i]*(y_inv**i) for i in range(len(Hi))]),H1*x_ip,l,r,None,None]
    while True:
        data_ip = inner_product(data_ip)

        # we have reached the end of the recursion
        if len(data_ip) == 2:
            proof = Bulletproof()
            proof.V = V
            proof.A = A
            proof.S = S
            proof.T1 = T1
            proof.T2 = T2
            proof.taux1 = taux1
            proof.taux2 = taux2
            proof.mu = mu
            proof.L = L
            proof.R = R
            proof.a = data_ip[0]
            proof.b = data_ip[1]
            proof.t = t

            return proof

        # we are not done yet
        L.append(data_ip[-2])
        R.append(data_ip[-1])

# Verify a batch of multi-output proofs
# proofs: list of proof data lists
# N: number of bits in range
#
# returns: True if all proofs are valid
def verify(proofs,N):
    # determine the length of the longest proof
    max_MN = 2**max([len(proof.L) for proof in proofs])

    # curve points
    Gi = PointVector([hash_to_point('Gi ' + str(i)) for i in range(max_MN)])
    Hi = PointVector([hash_to_point('Hi ' + str(i)) for i in range(max_MN)])

    # set up weighted aggregates
    y01 = Scalar(0)
    y02 = Scalar(0)
    y1 = Scalar(0)
    z1 = Scalar(0)
    z3 = Scalar(0)
    z4 = [Scalar(0)]*max_MN
    z5 = [Scalar(0)]*max_MN
    scalars = ScalarVector([]) # for final check
    points = PointVector([]) # for final check

    # run through each proof
    for proof in proofs:
        clear_cache()

        V = proof.V
        A = proof.A
        S = proof.S
        T1 = proof.T1
        T2 = proof.T2
        taux1 = proof.taux1
        taux2 = proof.taux2
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

        # reconstruct all challenges
        for v in V:
            mash(v)
        mash(A)
        mash(S)
        if cache == Scalar(0):
            raise ArithmeticError
        y = cache
        y_inv = y.invert()
        mash('')
        if cache == Scalar(0):
            raise ArithmeticError
        z = cache
        mash(T1)
        mash(T2)
        if cache == Scalar(0):
            raise ArithmeticError
        x = cache
        mash(taux1)
        mash(taux2)
        mash(mu)
        mash(t)
        if cache == Scalar(0):
            raise ArithmeticError
        x_ip = cache

        y01 += taux1*weight_y
        y02 += taux2*weight_y
        
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
            mash(L[i])
            mash(R[i])
            if cache == Scalar(0):
                raise ArithmeticError
            W.append(cache)
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
    scalars.append(-y01-z1)
    points.append(G)
    scalars.append(-y02)
    points.append(H2)
    scalars.append(-y1+z3)
    points.append(H1)
    for i in range(max_MN):
        scalars.append(-z4[i])
        points.append(Gi[i])
        scalars.append(-z5[i])
        points.append(Hi[i])

    if not dumb25519.multiexp(scalars,points) == dumb25519.Z:
        raise ArithmeticError('Bad z check!')

    return True
