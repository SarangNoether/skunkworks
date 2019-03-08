import dumb25519
from dumb25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point

if not dumb25519.VERSION == 0.2:
    raise Exception('Library version mismatch!')

cache = '' # rolling transcript hash
inv8 = Scalar(8).invert()
N = 64 # bits in range

# Stage A proof components
class ProofA:
    V = None
    A = None
    S = None

# Stage B proof components
class ProofB:
    T1 = None
    T2 = None

# Stage C proof components
class ProofC:
    taux = None
    mu = None
    l = None
    r = None

# Final aggregated proof
class Proof:
    V = None
    A = None
    S = None
    T1 = None
    T2 = None
    taux = None
    mu = None
    L = None
    R = None
    a = None
    b = None
    t = None
    
    # challenges; only used for state
    x = None
    y = None
    z = None

# Internal player state
class PlayerState:
    k = None # player index
    gamma = None
    aL = None
    aR = None
    sL = None
    sR = None
    alpha = None
    rho = None
    y = None
    z = None
    tau1 = None
    tau2 = None
    l0 = None
    l1 = None
    r0 = None
    r1 = None

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
# l: int; minimum power not included
# m: int; minimum power included (optional)
#
# returns: ScalarVector
def exp_scalar(s,l,m=0):
    return ScalarVector([s**i for i in range(m,l)])

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

# Generate an A-proof
# V: amount value
# gamma: mask
# k: player index
# seed: if set, random seed
#
# returns: ProofA object
def prove_A(v,gamma,k,seed=None):
    if seed is not None:
        dumb25519.set_seed(seed)

    # internal state
    state = PlayerState()
    state.k = k

    # curve points
    G = dumb25519.G
    H = hash_to_point('pybullet H')
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(k*N,(k+1)*N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(k*N,(k+1)*N)])

    # set amount commitment
    V = (H*v + G*gamma)*inv8
    aL = scalar_to_bits(v,N)

    # set bit array
    aR = ScalarVector([])
    for bit in aL.scalars:
        aR.append(bit-Scalar(1))

    alpha = random_scalar()
    A = (Gi*aL + Hi*aR + G*alpha)*inv8

    sL = ScalarVector([random_scalar()]*N)
    sR = ScalarVector([random_scalar()]*N)
    rho = random_scalar()
    S = (Gi*sL + Hi*sR + G*rho)*inv8

    # update state
    state.gamma = gamma
    state.aL = aL
    state.aR = aR
    state.sL = sL
    state.sR = sR
    state.alpha = alpha
    state.rho = rho

    # construct proof share
    proof = ProofA()
    proof.V = V
    proof.A = A
    proof.S = S
    return proof,state

# Generate a B-proof
# state: player state (PlayerState)
# y,z: dealer challenges
# seed: if set, random seed
#
# returns: ProofB object
def prove_B(state,y,z,seed=None):
    if seed is not None:
        dumb25519.set_seed(seed)

    # check for bad challenges
    if y == Scalar(0) or z == Scalar(0):
        raise ValueError('Bad challenge!')

    # curve points
    G = dumb25519.G
    H = hash_to_point('pybullet H')

    # restore state
    aL = state.aL
    aR = state.aR
    sL = state.sL
    sR = state.sR
    k = state.k

    # polynomial coefficients
    l0 = aL - ScalarVector([z]*N)
    l1 = sL

    r0 = aR + ScalarVector([z]*N)
    r0 = r0*exp_scalar(y,(k+1)*N,k*N)
    r0 += exp_scalar(Scalar(2),N)*z**(2+k)
    r1 = exp_scalar(y,(k+1)*N,k*N)*sR

    # build the polynomials
    t0 = l0**r0
    t1 = l0**r1 + l1**r0
    t2 = l1**r1

    tau1 = random_scalar()
    tau2 = random_scalar()
    T1 = (H*t1 + G*tau1)*inv8
    T2 = (H*t2 + G*tau2)*inv8

    # update state
    state.y = y
    state.z = z
    state.tau1 = tau1
    state.tau2 = tau2
    state.l0 = l0
    state.l1 = l1
    state.r0 = r0
    state.r1 = r1

    # construct proof share
    proof = ProofB()
    proof.T1 = T1
    proof.T2 = T2
    return proof,state

# Generate a C-proof
# state: player state (PlayerState)
# x: dealer challenge
# seed: if set, random seed
#
# returns: ProofC object
def prove_C(state,x,seed=None):
    if seed is not None:
        dumb25519.set_seed(seed)

    # check for bad challenge
    if x == Scalar(0):
        raise ValueError('Bad challenge!')

    # restore state
    tau1 = state.tau1
    tau2 = state.tau2
    z = state.z
    gamma = state.gamma
    rho = state.rho
    alpha = state.alpha
    k = state.k
    l0 = state.l0
    l1 = state.l1
    r0 = state.r0
    r1 = state.r1

    taux = tau1*x + tau2*(x**2) + z**(2+k)*gamma
    mu = x*rho+alpha
    
    l = l0 + l1*x
    r = r0 + r1*x

    # construct proof share
    proof = ProofC()
    proof.taux = taux
    proof.mu = mu
    proof.l = l
    proof.r = r
    return proof

# Aggregate A-proofs and produce challenges
# shares: list of shares in player order (ProofA)
#
# returns: proof (Proof)
def aggregate_A(shares):
    clear_cache()

    # aggregate points
    proof = Proof()
    proof.V = [share.V for share in shares]
    proof.A = dumb25519.Z
    proof.S = dumb25519.Z
    for share in shares:
        mash(share.V)
        proof.A += share.A
        proof.S += share.S
    mash(proof.A)
    mash(proof.S)
    proof.y = cache
    mash('')
    proof.z = cache

    return proof

# Aggregate B-proofs and produce challenges
# shares: list of shares in player order (ProofB)
# proof: proof (Proof)
#
# returns: proof (Proof)
def aggregate_B(shares,proof):
    global cache
    cache = proof.z

    # aggregate points
    proof.T1 = dumb25519.Z
    proof.T2 = dumb25519.Z
    for share in shares:
        proof.T1 += share.T1
        proof.T2 += share.T2
    mash(proof.T1)
    mash(proof.T2)
    proof.x = cache

    return proof

# Aggregate C-proofs and produce final proof elements
# shares: list of shares in player order (ProofC)
# proof: proof (Proof)
#
# returns: proof (Proof)
def aggregate_C(shares,proof):
    global cache
    cache = proof.x

    M = len(shares)

    # aggregate points
    proof.taux = Scalar(0)
    proof.mu = Scalar(0)
    l = ScalarVector([])
    r = ScalarVector([])
    for share in shares:
        proof.taux += share.taux
        proof.mu += share.mu
        l.extend(share.l)
        r.extend(share.r)
    proof.t = l**r
    mash(proof.taux)
    mash(proof.mu)
    mash(proof.t)

    # curve points
    G = dumb25519.G
    H = hash_to_point('pybullet H')
    Gi = PointVector([hash_to_point('pybullet Gi ' + str(i)) for i in range(M*N)])
    Hi = PointVector([hash_to_point('pybullet Hi ' + str(i)) for i in range(M*N)])

    x_ip = cache # challenge
    L = PointVector([])
    R = PointVector([])
    y_inv = proof.y.invert()
   
    # initial inner product inputs
    data_ip = [Gi,PointVector([Hi[i]*(y_inv**i) for i in range(len(Hi))]),H*x_ip,l,r,None,None]
    while True:
        data_ip = inner_product(data_ip)

        # we have reached the end of the recursion
        if len(data_ip) == 2:
            proof.L = L
            proof.R = R
            proof.a = data_ip[0]
            proof.b = data_ip[1]
            return proof

        # we are not done yet
        L.append(data_ip[-2])
        R.append(data_ip[-1])

# Verify a batch of aggregated proofs
# proofs: list of proofs (Proof)
#
# returns: True if all proofs are valid
def verify(proofs):
    # determine the length of the longest proof
    max_MN = 2**max([len(proof.L) for proof in proofs])

    # curve points
    Z = dumb25519.Z
    G = dumb25519.G
    H = hash_to_point('pybullet H')
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
        clear_cache()

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
            raise ValueError

        # reconstruct all challenges
        for v in V:
            mash(v)
        mash(A)
        mash(S)
        if cache == Scalar(0):
            raise ValueError
        y = cache
        y_inv = y.invert()
        mash('')
        if cache == Scalar(0):
            raise ValueError
        z = cache
        mash(T1)
        mash(T2)
        if cache == Scalar(0):
            raise ValueError
        x = cache
        mash(taux)
        mash(mu)
        mash(t)
        if cache == Scalar(0):
            raise ValueError
        x_ip = cache

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
            mash(L[i])
            mash(R[i])
            if cache == Scalar(0):
                raise ValueError
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
    scalars.append(-y0-z1)
    points.append(G)
    scalars.append(-y1+z3)
    points.append(H)
    for i in range(max_MN):
        scalars.append(-z4[i])
        points.append(Gi[i])
        scalars.append(-z5[i])
        points.append(Hi[i])

    # at least one proof is invalid
    if not dumb25519.multiexp(scalars,points) == Z:
        raise ArithmeticError('Invalid proof!')

    # all proofs are valid
    return True
