from common import *
from dumb25519 import hash_to_point, random_scalar, Scalar, hash_to_scalar

# Internal proof state
class State:
    m = None
    n = None
    sigma = None
    a = None
    rA = None
    rB = None
    rC = None
    rD = None
    v = None
    r = None
    rho = None
    tau = None
    gammas = None

    x = None # Fiat-Shamir challenge

# Proof structure
class Proof:
    A = None
    B = None
    C = None
    D = None
    G = None
    Q = None
    f = None
    zA = None
    zC = None
    zV = None
    zR = None

    def __repr__(self):
        temp = '<GrothProof> '
        temp += 'A:'+repr(self.A)+'|'
        temp += 'B:'+repr(self.B)+'|'
        temp += 'C:'+repr(self.C)+'|'
        temp += 'D:'+repr(self.D)+'|'
        temp += 'G:'+repr(self.G)+'|'
        temp += 'Q:'+repr(self.Q)+'|'
        temp += 'f:'+repr(self.f)+'|'
        temp += 'zA:'+repr(self.zA)+'|'
        temp += 'zC:'+repr(self.zC)+'|'
        temp += 'zV:'+repr(self.zV)+'|'
        temp += 'zR:'+repr(self.zR)
        return temp

# Compute an aggregate Fiat-Shamir challenge
def challenge(proofs):
    A = [proof.A for proof in proofs]
    B = [proof.B for proof in proofs]
    C = [proof.C for proof in proofs]
    D = [proof.D for proof in proofs]
    G = [proof.G for proof in proofs]
    Q = [proof.Q for proof in proofs]
    return hash_to_scalar(A,B,C,D,G,Q)

# Double-blinded Pedersen matrix commitment
def com_matrix(v,r):
    C = dumb25519.Z
    for j in range(len(v)):
        for i in range(len(v[0])):
            C += hash_to_point('Gi',j,i)*v[j][i]
    return C

# Double-blinded Pedersen commitment
def comm(s,v,r):
    return G*s + H1*v + H2*r

# Decompose a value with given base and size
def decompose(val,base,size,t=int):
    temp_val = val # for reconstruction testing
    r = []
    for i in range(size-1,-1,-1):
        slot = base**i
        r.append(int(val/slot))
        val -= slot*r[-1]
    r = list(reversed(r))

    # Reconstruct to ensure correct decomposition
    if t == int:
        temp = 0
    else:
        temp = Scalar(0)

    for i in range(len(r)):
        temp += r[i]*base**i
    if not temp == temp_val:
        raise ArithmeticError('Decomposition failed!')

    # Return int list or Scalar list
    if t == int:
        return r

    s = []
    for i in r:
        s.append(Scalar(i))
    return s

# Kronecker delta
def delta(x,y):
    if x == y:
        return Scalar(1)
    return Scalar(0)

# Compute a convolution
def convolve(x,y,size=None):
    r = [Scalar(0)]*(len(x)+len(y))
    for i in range(len(x)):
        for j in range(len(y)):
            r[i+j] += x[i]*y[j]

    # Pad with zeros
    if size is not None and size > len(r):
        for i in range(size-len(r)):
            r.append(Scalar(0))

    return r

# Perform a commitment-to-zero proof
#
# INPUT
#  M: list of double-blinded Pedersen commitments such that len(M) == n**m
#  l: index such that M[l] is a commitment to zero
#  v: first Pedersen blinder for M[l]
#  r: second Pedersen blinder for M[l]
#  n,m: dimensions such that len(M) == n**m
# RETURNS
#  proof structure
#  internal state
def prove_initial(M,l,v,r,n,m):
    # Size check
    if not len(M) == n**m:
        return IndexError('Bad size decomposition!')
    N = len(M)

    # Reconstruct the known commitment
    if not comm(Scalar(0),v,r) == M[l]:
        return ValueError('Bad known commitment!')

    rA = random_scalar()
    rB = random_scalar()
    rC = random_scalar()
    rD = random_scalar()

    # Commit to zero-sum blinders
    a = [[random_scalar()]*n for _ in range(m)]
    for j in range(m):
        a[j][0] = Scalar(0)
        for i in range(1,n):
            a[j][0] -= a[j][i]
    A = com_matrix(a,rA)

    # Commit to decomposition bits
    decomp_l = decompose(l,n,m)
    sigma = [[None]*n for _ in range(m)]
    for j in range(m):
        for i in range(n):
            sigma[j][i] = delta(decomp_l[j],i)
    B = com_matrix(sigma,rB)

    # Commit to a/sigma relationships
    a_sigma = [[Scalar(0)]*n for _ in range(m)]
    for j in range(m):
        for i in range(n):
            a_sigma[j][i] = a[j][i]*(Scalar(1) - Scalar(2)*sigma[j][i])
    C = com_matrix(a_sigma,rC)
    
    # Commit to squared a-values
    a_sq = [[Scalar(0)]*n for _ in range(m)]
    for j in range(m):
        for i in range(n):
            a_sq[j][i] = -a[j][i]*a[j][i]
    D = com_matrix(a_sq,rD)

    # Compute p coefficients
    p = [[Scalar(0)]*m for _ in range(N)]
    for k in range(N):
        decomp_k = decompose(k,n,m)
        p[k] = [a[0][decomp_k[0]],delta(decomp_l[0],decomp_k[0])]
        
        for j in range(1,m):
            p[k] = convolve(p[k],[a[j][decomp_k[j]],delta(decomp_l[j],decomp_k[j])],m)

    # Generate proof values
    G = [dumb25519.Z]*m
    Q = [dumb25519.Z]*m
    rho = [None]*m
    tau = [None]*m
    gammas = [None]*m
    for j in range(m):
        rho[j] = random_scalar()
        tau[j] = random_scalar()
        gamma = random_scalar()
        gammas[j] = gamma
        for i in range(N):
            G[j] += M[i]*p[i][j]
        G[j] -= H2*gamma
        Q[j] = comm(Scalar(0),rho[j],tau[j]) + H2*gamma

    # Assemble state
    state = State()
    state.m = m
    state.n = n
    state.sigma = sigma
    state.a = a
    state.rA = rA
    state.rB = rB
    state.rC = rC
    state.rD = rD
    state.v = v
    state.r = r
    state.rho = rho
    state.tau = tau
    state.gammas = gammas

    # Partial proof
    proof = Proof()
    proof.A = A
    proof.B = B
    proof.C = C
    proof.D = D
    proof.G = G
    proof.Q = Q

    return proof,state

# Complete a partial proof
def prove_final(proof,state):
    x = state.x # aggregate Fiat-Shamir challenge

    # Recover state
    m = state.m
    n = state.n
    sigma = state.sigma
    a = state.a
    rA = state.rA
    rB = state.rB
    rC = state.rC
    rD = state.rD
    v = state.v
    r = state.r
    rho = state.rho
    tau = state.tau
    gammas = state.gammas

    f = [[None]*n for _ in range(m)]
    for j in range(m):
        for i in range(1,n):
            f[j][i] = sigma[j][i]*x + a[j][i]

    zA = rB*x + rA
    zC = rC*x + rD
    zV = v*x**m
    zR = r*x**m
    for j in range(m):
        zV -= rho[j]*x**j
        zR -= tau[j]*x**j

    # Assemble proof
    proof.f = f
    proof.zA = zA
    proof.zC = zC
    proof.zV = zV
    proof.zR = zR

    return proof,gammas

# Verify a commitment-to-zero proof
#
# INPUT
#  M: list of double-blinded Pedersen commitments such that len(M) == n**m
#  proof: proof structure
#  n,m: dimensions such that len(M) == n**m
#  x: aggregate Fiat-Shamir challenge
# RETURNS
#  True if the proof is valid
def verify(M,proof,n,m,x):
    A = proof.A
    B = proof.B
    C = proof.C
    D = proof.D
    G = proof.G
    Q = proof.Q
    f = proof.f
    zA = proof.zA
    zC = proof.zC
    zV = proof.zV
    zR = proof.zR

    N = n**m

    for j in range(m):
        f[j][0] = x
        for i in range(1,n):
            f[j][0] -= f[j][i]

    # A/B check
    if not com_matrix(f,zA) == B*x + A:
        raise ArithmeticError('Failed A/B check!')

    # C/D check
    fx = [[None]*n for _ in range(m)]
    for j in range(m):
        for i in range(n):
            fx[j][i] = f[j][i]*(x-f[j][i])
    if not com_matrix(fx,zC) == C*x + D:
        raise ArithmeticError('Failed C/D check!')

    # Commitment check
    R = dumb25519.Z
    for i in range(N):
        s = Scalar(1)
        decomp_i = decompose(i,n,m)
        for j in range(m):
            s *= f[j][decomp_i[j]]
        R += M[i]*s
    for j in range(m):
        R -= (G[j] + Q[j])*x**j
    if not R == comm(Scalar(0),zV,zR):
        raise ArithmeticError('Failed commitment check!')

    return True
