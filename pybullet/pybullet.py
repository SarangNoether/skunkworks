import dumb25519
from dumb25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point, multiexp
import transcript

inv8 = Scalar(8).invert()

# Proof structure
class Bulletproof:
    def __init__(self,V,A,A1,B,r1,s1,d1,L,R):
        self.V = V
        self.A = A
        self.A1 = A1
        self.B = B
        self.r1 = r1
        self.s1 = s1
        self.d1 = d1
        self.L = L
        self.R = R

# Data for a round of the inner product argument
class InnerProductRound:
    def __init__(self,Gi,Hi,G,H,P,a,b,alpha,y,tr):
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

        # Transcript
        self.tr = tr

# Compute a weighted inner product
#
# INPUTS
#   a,b: (ScalarVector)
#   y: weight (Scalar)
# OUTPUTS
#   Scalar
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

# Generate a vector of powers of a scalar, in either direction, indexed at 1
#
# INPUTS
#   s: (Scalar)
#   l: number of powers to include (int)
#   desc: whether to use a descending indexing (bool)
# OUTPUTS
#   ScalarVector
def exp_scalar(s,l,desc=False):
    if desc:
        return ScalarVector([s**(l-i) for i in range(l)])
    else:
        return ScalarVector([s**(i+1) for i in range(l)])

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
    n = len(data.Gi)

    # Sanity check
    if not data.P == data.Gi**data.a + data.Hi**data.b + data.G*wip(data.a,data.b,data.y) + data.H*data.alpha:
        raise ArithmeticError('Bad prover round!')

    if n == 1:
        data.done = True

        # Random masks
        r = random_scalar()
        s = random_scalar()
        d = random_scalar()
        eta = random_scalar()

        data.A = data.Gi[0]*r + data.Hi[0]*s + data.G*(r*data.y*data.b[0] + s*data.y*data.a[0]) + data.H*d
        data.B = data.G*(r*data.y*s) + data.H*eta

        data.tr.update(data.A)
        data.tr.update(data.B)
        e = data.tr.challenge()

        data.r1 = r + data.a[0]*e
        data.s1 = s + data.b[0]*e
        data.d1 = eta + d*e + data.alpha*e**2

        if not data.P*e**2 + data.A*e + data.B == data.Gi[0]*(data.r1*e) + data.Hi[0]*(data.s1*e) + data.G*(data.r1*data.y*data.s1) + data.H*data.d1:
            raise ArithmeticError('Bad manual verifier!')

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

    data.tr.update(data.L[-1])
    data.tr.update(data.R[-1])
    e = data.tr.challenge()

    data.Gi = G1*e.invert() + G2*(e*data.y.invert()**n)
    data.Hi = H1*e + H2*e.invert()
    data.P = data.L[-1]*e**2 + data.P + data.R[-1]*e.invert()**2

    data.a = a1*e + a2*data.y**n*e.invert()
    data.b = b1*e.invert() + b2*e
    data.alpha = dL*e**2 + data.alpha + dR*e.invert()**2

# Generate a multi-output proof
#
# INPUTS
#   data: list of value/mask pairs (Scalars)
#   N: number of bits in range (int)
# OUTPUTS
#   Bulletproof
def prove(data,N):
    tr = transcript.Transcript('Bulletproof+')
    M = len(data) # aggregation factor

    # Curve points
    G = dumb25519.G
    H = hash_to_point('pybullet H')
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(M*N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(M*N)])

    one_MN = ScalarVector([Scalar(1) for _ in range(M*N)])

    # Set amount commitments
    V = PointVector([])
    aL = ScalarVector([])
    for v,gamma in data:
        V.append(G*v + H*gamma)
        tr.update(V[-1])
        aL.extend(scalar_to_bits(v,N))

    # Set offset bit array
    aR = aL - one_MN

    alpha = random_scalar()
    A = Gi**aL + Hi**aR + H*alpha

    # Get challenges
    tr.update(A)
    y = tr.challenge()
    z = tr.challenge()

    d = ScalarVector([])
    for j in range(M):
        for i in range(N):
            d.append(z**(2*(j+1))*Scalar(2)**i)

    # Build the proof element incrementally
    Ahat = A - Gi**(one_MN*z)
    Ahat += Hi**(d*exp_scalar(y,M*N,desc=True) + one_MN*z)
    for j in range(M):
        Ahat += V[j]*(z**(2*(j+1))*y**(M*N+1))
    Ahat += G*(one_MN**exp_scalar(y,M*N)*z - one_MN**d*y**(M*N+1)*z - one_MN**exp_scalar(y,M*N)*z**2)
    
    # Prepare for inner product
    aL1 = aL - one_MN*z
    aR1 = aR + d*exp_scalar(y,M*N,desc=True) + one_MN*z
    alpha1 = alpha
    for j in range(M):
        gamma = data[j][1]
        alpha1 += z**(2*(j+1))*gamma*y**(M*N+1)

    # Sanity check on WIP relation
    if not Ahat == Gi**aL1 + Hi**aR1 + G*wip(aL1,aR1,y) + H*alpha1:
        raise ArithmeticError('Bad prover relation!')

    # Initial inner product inputs
    data = InnerProductRound(Gi,Hi,G,H,Ahat,aL1,aR1,alpha1,y,tr)
    while True:
        inner_product(data)

        # We have reached the end of the recursion
        if data.done:
            return Bulletproof(V,A,data.A,data.B,data.r1,data.s1,data.d1,data.L,data.R)

# Verify a multi-output proof
# TODO: add batching and efficient verifier!
#
# INPUTS
#   proof: proofs (Bulletproof)
#   N: number of bits in range (int)
def verify(proof,N):
    M = len(proof.V)

    # curve points
    Z = dumb25519.Z
    G = dumb25519.G
    H = hash_to_point('pybullet H')
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(M*N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(M*N)])

    one_MN = ScalarVector([Scalar(1) for _ in range(M*N)])

    # Start transcript
    tr = transcript.Transcript('Bulletproof+')

    for V in proof.V:
        tr.update(V)
    tr.update(proof.A)
    y = tr.challenge()
    if y == Scalar(0):
        raise ArithmeticError('Bad verifier challenge!')
    z = tr.challenge()
    if z == Scalar(0):
        raise ArithmeticError('Bad verifier challenge!')

    # Build the inner product input
    d = ScalarVector([])
    for j in range(M):
        for i in range(N):
            d.append(z**(2*(j+1))*Scalar(2)**i)

    # Build the proof element incrementally
    Ahat = proof.A - Gi**(one_MN*z)
    Ahat += Hi**(d*exp_scalar(y,M*N,desc=True) + one_MN*z)
    for j in range(M):
        Ahat += proof.V[j]*(z**(2*(j+1))*y**(M*N+1))
    Ahat += G*(one_MN**exp_scalar(y,M*N)*z - one_MN**d*y**(M*N+1)*z - one_MN**exp_scalar(y,M*N)*z**2)

    # Final multiscalar multiplication data
    scalars = ScalarVector([])
    points = PointVector([])

    # Reconstruct challenges
    challenges = ScalarVector([]) # challenges
    for j in range(len(proof.L)):
        tr.update(proof.L[j])
        tr.update(proof.R[j])
        challenges.append(tr.challenge())
        if challenges[j] == Scalar(0):
            raise ArithmeticError('Bad verifier challenge!')
    challenges_inv = challenges.invert()
    tr.update(proof.A1)
    tr.update(proof.B)
    e = tr.challenge()
    if e == Scalar(0):
        raise ArithmeticError('Bad verifier challenge!')

    # Aggregate the generator scalars
    for i in range(M*N):
        index = i
        g = proof.r1*e*y.invert()**i
        h = proof.s1*e
        for j in range(len(proof.L)-1,-1,-1):
            J = len(challenges)-j-1
            base_power = 2**j
            if index/base_power == 0: # rounded down
                g *= challenges_inv[J]
                h *= challenges[J]
            else:
                g *= challenges[J]
                h *= challenges_inv[J]
                index -= base_power
        scalars.append(g)
        points.append(Gi[i])
        scalars.append(h)
        points.append(Hi[i])

    # Remaining terms
    scalars.append(proof.r1*y*proof.s1)
    points.append(G)
    scalars.append(proof.d1)
    points.append(H)

    scalars.append(-e)
    points.append(proof.A1)
    scalars.append(-Scalar(1))
    points.append(proof.B)

    scalars.append(-e**2)
    points.append(Ahat)
    for j in range(len(proof.L)):
        scalars.append(-e**2*challenges[j]**2)
        points.append(proof.L[j])
        scalars.append(-e**2*challenges_inv[j]**2)
        points.append(proof.R[j])

    if not multiexp(scalars,points) == Z:
        raise ArithmeticError('Failed verification!')
