import dumb25519
from dumb25519 import Scalar, ScalarVector, PointVector, random_scalar, hash_to_point, hash_to_scalar, multiexp
import transcript

inv8 = Scalar(8).invert()

# Proof structure
class Bulletproof:
    def __init__(self,V,A,A1,B,r1,s1,d1,L,R,seed,gammas):
        self.V = V
        self.A = A
        self.A1 = A1
        self.B = B
        self.r1 = r1
        self.s1 = s1
        self.d1 = d1
        self.L = L
        self.R = R

        # NOTE: not public data; here for convenience only
        self.seed = seed
        self.gammas = gammas

# Data for a round of the inner product argument
class InnerProductRound:
    def __init__(self,Gi,Hi,G,H,a,b,alpha,y,tr,seed):
        # Common data
        self.Gi = Gi
        self.Hi = Hi
        self.G = G
        self.H = H
        self.y = y
        self.done = False
        self.round = 0 # round count

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

        # Seed for auxiliary data embedding
        self.seed = seed

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
        d = random_scalar() if data.seed is None else hash_to_scalar(data.seed,'d')
        eta = random_scalar() if data.seed is None else hash_to_scalar(data.seed,'eta')

        data.A = (data.Gi[0]*r + data.Hi[0]*s + data.H*(r*data.y*data.b[0] + s*data.y*data.a[0]) + data.G*d)*inv8
        data.B = (data.H*(r*data.y*s) + data.G*eta)*inv8

        data.tr.update(data.A)
        data.tr.update(data.B)
        e = data.tr.challenge()

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

    dL = random_scalar() if data.seed is None else hash_to_scalar(data.seed,'dL',data.round)
    dR = random_scalar() if data.seed is None else hash_to_scalar(data.seed,'dR',data.round)

    cL = wip(a1,b2,data.y)
    cR = wip(a2*data.y**n,b1,data.y)
    data.L.append((G2**(a1*data.y.invert()**n) + H1**b2 + data.H*cL + data.G*dL)*inv8)
    data.R.append((G1**(a2*data.y**n) + H2**b1 + data.H*cR + data.G*dR)*inv8)

    data.tr.update(data.L[-1])
    data.tr.update(data.R[-1])
    e = data.tr.challenge()

    data.Gi = G1*e.invert() + G2*(e*data.y.invert()**n)
    data.Hi = H1*e + H2*e.invert()

    data.a = a1*e + a2*data.y**n*e.invert()
    data.b = b1*e.invert() + b2*e
    data.alpha = dL*e**2 + data.alpha + dR*e.invert()**2

    data.round += 1

# Generate a multi-output proof
#
# INPUTS
#   data: list of value/mask pairs (Scalars)
#   N: number of bits in range (int)
#   seed: seed for auxiliary data (hashable, optional)
#   aux: auxiliary data to embed (Scalar, optional)
# OUTPUTS
#   Bulletproof
def prove(data,N,seed=None,aux=None):
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
        V.append((H*v + G*gamma)*inv8)
        tr.update(V[-1])
        aL.extend(scalar_to_bits(v,N))

    # Set offset bit array
    aR = aL - one_MN

    alpha = random_scalar() if seed is None else hash_to_scalar(seed,V,'alpha') + aux
    A = (Gi**aL + Hi**aR + G*alpha)*inv8

    # Get challenges
    tr.update(A)
    y = tr.challenge()
    z = tr.challenge()

    d = ScalarVector([])
    for j in range(M):
        for i in range(N):
            d.append(z**(2*(j+1))*Scalar(2)**i)

    # Prepare for inner product
    aL1 = aL - one_MN*z
    aR1 = aR + d*exp_scalar(y,M*N,desc=True) + one_MN*z
    alpha1 = alpha
    for j in range(M):
        gamma = data[j][1]
        alpha1 += z**(2*(j+1))*gamma*y**(M*N+1)

    # Initial inner product inputs
    ip_data = InnerProductRound(Gi,Hi,G,H,aL1,aR1,alpha1,y,tr,seed)
    while True:
        inner_product(ip_data)

        # We have reached the end of the recursion
        if ip_data.done:
            return Bulletproof(V,A,ip_data.A,ip_data.B,ip_data.r1,ip_data.s1,ip_data.d1,ip_data.L,ip_data.R,seed,[datum[1] for datum in data])

# Verify a batch of multi-output proofs
#
# INPUTS
#   proofs: list of proofs (Bulletproof)
#   N: number of bits in range (int)
# OUTPUTS
#   auxiliary data if all proofs are valid
def verify(proofs,N):
    max_MN = 2**max([len(proof.L) for proof in proofs]) # length of the largest inner product input

    # Weighted coefficients for common generators
    G_scalar = Scalar(0)
    H_scalar = Scalar(0)
    Gi_scalars = ScalarVector([Scalar(0)]*max_MN)
    Hi_scalars = ScalarVector([Scalar(0)]*max_MN)

    # Final multiscalar multiplication data
    scalars = ScalarVector([])
    points = PointVector([])

    # Curve points
    Z = dumb25519.Z
    G = dumb25519.G
    H = hash_to_point('pybullet H')
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(max_MN)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(max_MN)])

    # Store auxiliary data
    aux = []

    # Process each proof and add it to the batch
    for proof in proofs:
        # Sanity checks
        if not isinstance(proof, Bulletproof):
            raise TypeError

        V = proof.V
        A = proof.A
        A1 = proof.A1
        B = proof.B
        r1 = proof.r1
        s1 = proof.s1
        d1 = proof.d1
        L = proof.L
        R = proof.R
        seed = proof.seed
        gammas = proof.gammas

        if not len(L) == len(R):
            raise IndexError
        if not 2**len(L) == len(V)*N:
            raise IndexError

        # Helpful quantities
        M = len(V)
        one_MN = ScalarVector([Scalar(1) for _ in range(M*N)])

        # Batch weight
        weight = random_scalar()
        if weight == Scalar(0):
            raise ArithmeticError

        # Start transcript
        tr = transcript.Transcript('Bulletproof+')

        # Reconstruct challenges
        for V_ in V:
            tr.update(V_)
        tr.update(proof.A)
        y = tr.challenge()
        if y == Scalar(0):
            raise ArithmeticError('Bad verifier challenge!')
        z = tr.challenge()
        if z == Scalar(0):
            raise ArithmeticError('Bad verifier challenge!')

        # Start preparing data
        d = ScalarVector([])
        for j in range(M):
            for i in range(N):
                d.append(z**(2*(j+1))*Scalar(2)**i)

        # Reconstruct challenges
        challenges = ScalarVector([]) # challenges
        for j in range(len(L)):
            tr.update(L[j])
            tr.update(R[j])
            challenges.append(tr.challenge())
            if challenges[j] == Scalar(0):
                raise ArithmeticError('Bad verifier challenge!')
        challenges_inv = challenges.invert()
        tr.update(A1)
        tr.update(B)
        e = tr.challenge()
        if e == Scalar(0):
            raise ArithmeticError('Bad verifier challenge!')

        # Recover auxiliary data if present
        if seed is not None and gammas is not None:
            aux.append(d1 - hash_to_scalar(seed,'eta') - e*hash_to_scalar(seed,'d'))

            temp = Scalar(0)
            for j in range(len(challenges)):
                temp += hash_to_scalar(seed,'dL',j)*challenges[j]**2 + hash_to_scalar(seed,'dR',j)*challenges_inv[j]**2
            aux[-1] -= e**2*temp
            aux[-1] -= e**2*hash_to_scalar(seed,V,'alpha')
            
            temp = Scalar(0)
            for j in range(1,len(gammas)+1):
                temp += z**(2*j)*gammas[j-1]
            aux[-1] -= e**2*y**(M*N+1)*temp

            aux[-1] *= e.invert()**2

        # Aggregate the generator scalars
        for i in range(M*N):
            index = i
            g = r1*e*y.invert()**i
            h = s1*e
            for j in range(len(L)-1,-1,-1):
                J = len(challenges)-j-1
                base_power = 2**j
                if index/base_power == 0: # rounded down
                    g *= challenges_inv[J]
                    h *= challenges[J]
                else:
                    g *= challenges[J]
                    h *= challenges_inv[J]
                    index -= base_power
            Gi_scalars[i] += weight*(g + e**2*z)
            Hi_scalars[i] += weight*(h - e**2*(d[i]*y**(M*N-i)+z))

        # Remaining terms
        for j in range(M):
            scalars.append(weight*(-e**2*z**(2*(j+1))*y**(M*N+1)))
            points.append(V[j]*Scalar(8))

        H_scalar += weight*(r1*y*s1 + e**2*(y**(M*N+1)*z*one_MN**d + (z**2-z)*one_MN**exp_scalar(y,M*N)))
        G_scalar += weight*d1

        scalars.append(weight*-e)
        points.append(A1*Scalar(8))
        scalars.append(-weight)
        points.append(B*Scalar(8))
        scalars.append(weight*-e**2)
        points.append(A*Scalar(8))

        for j in range(len(L)):
            scalars.append(weight*(-e**2*challenges[j]**2))
            points.append(L[j]*Scalar(8))
            scalars.append(weight*(-e**2*challenges_inv[j]**2))
            points.append(R[j]*Scalar(8))

    # Common generators
    scalars.append(G_scalar)
    points.append(G)
    scalars.append(H_scalar)
    points.append(H)
    for i in range(max_MN):
        scalars.append(Gi_scalars[i])
        points.append(Gi[i])
        scalars.append(Hi_scalars[i])
        points.append(Hi[i])

    if not multiexp(scalars,points) == Z:
        raise ArithmeticError('Failed verification!')
    
    return aux
