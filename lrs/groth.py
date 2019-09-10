# Proof-of-concept implementation of https://github.com/monero-project/research-lab/issues/56

from dumb25519 import hash_to_point, random_scalar, Scalar, hash_to_scalar, G, random_point
import dumb25519

H = hash_to_point('H')

# Proof structure
class Proof:
    def __init__(self):
        self.J = None
        self.A = None
        self.B = None
        self.C = None
        self.D = None
        self.X = None
        self.Y = None
        self.Z = None
        self.f = None
        self.zA = None
        self.zC = None
        self.zR = None
        self.zS = None

    def __repr__(self):
        temp = '<GrothProof> '
        temp += 'J:'+repr(self.J)+'|'
        temp += 'A:'+repr(self.A)+'|'
        temp += 'B:'+repr(self.B)+'|'
        temp += 'C:'+repr(self.C)+'|'
        temp += 'D:'+repr(self.D)+'|'
        temp += 'X:'+repr(self.G)+'|'
        temp += 'Y:'+repr(self.Q)+'|'
        temp += 'Z:'+repr(self.Z)+'|'
        temp += 'f:'+repr(self.f)+'|'
        temp += 'zA:'+repr(self.zA)+'|'
        temp += 'zC:'+repr(self.zC)+'|'
        temp += 'zR:'+repr(self.zR)+'|'
        temp += 'zS:'+repr(self.zS)
        return temp

# Pedersen vector commitment
def com_matrix(v,r):
    C = dumb25519.Z
    for i in range(len(v)):
        for j in range(len(v[0])):
            C += hash_to_point('Gi',i,j)*v[i][j]
    C += r*H
    return C

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

# Perform a double-base commitment-to-zero proof
#
# INPUT
#  M: public key list
#  P: value commitment list
#  l: index such that M[l], C[l] are commitments to zero
#  r: Pedersen blinder for M[l]
#  s: Pedersen blinder for C[l]
#  m: dimension such that len(M) == len(C) == 2**m
# RETURNS
#  proof structure
def prove(M,P,l,r,s,m):
    n = 2 # binary decomposition

    # Size check
    if not len(M) == n**m or not len(P) == n**m:
        raise IndexError('Bad size decomposition!')
    N = len(M)

    # Construct the tag
    J = r.invert()*hash_to_point(M[l])

    # Reconstruct the known commitments
    if not M[l] == r*G:
        raise ValueError('Bad known public key!')
    if not P[l] == s*G:
        raise ValueError('Bad known value commitment!')

    rA = random_scalar()
    rB = random_scalar()
    rC = random_scalar()
    rD = random_scalar()

    # Commit to zero-sum blinders
    a = [[random_scalar() for _ in range(n)] for _ in range(m)]
    for j in range(m):
        a[j][0] = Scalar(0)
        for i in range(1,n):
            a[j][0] -= a[j][i]
    A = com_matrix(a,rA)

    # Commit to decomposition bits
    decomp_l = decompose(l,n,m)
    sigma = [[None for _ in range(n)] for _ in range(m)]
    for j in range(m):
        for i in range(n):
            sigma[j][i] = delta(decomp_l[j],i)
    B = com_matrix(sigma,rB)

    # Commit to a/sigma relationships
    a_sigma = [[Scalar(0) for _ in range(n)] for _ in range(m)]
    for j in range(m):
        for i in range(n):
            a_sigma[j][i] = a[j][i]*(Scalar(1) - Scalar(2)*sigma[j][i])
    C = com_matrix(a_sigma,rC)
    
    # Commit to squared a-values
    a_sq = [[Scalar(0) for _ in range(n)] for _ in range(m)]
    for j in range(m):
        for i in range(n):
            a_sq[j][i] = -a[j][i]*a[j][i]
    D = com_matrix(a_sq,rD)

    # Compute p coefficients
    p = [[Scalar(0) for _ in range(m)] for _ in range(N)]
    for k in range(N):
        decomp_k = decompose(k,n,m)
        p[k] = [a[0][decomp_k[0]],delta(decomp_l[0],decomp_k[0])]
        
        for j in range(1,m):
            p[k] = convolve(p[k],[a[j][decomp_k[j]],delta(decomp_l[j],decomp_k[j])],m)

    # Generate proof values
    X = [dumb25519.Z for _ in range(m)]
    Y = [dumb25519.Z for _ in range(m)]
    Z = [dumb25519.Z for _ in range(m)]
    rho = [random_scalar() for _ in range(m)]
    rho_Z = [random_scalar() for _ in range(m)]
    for j in range(m):
        for i in range(N):
            X[j] += M[i]*p[i][j]
            Y[j] += hash_to_point(M[i])*p[i][j]
            Z[j] += P[i]*p[i][j]
        X[j] += rho[j]*G
        Y[j] += rho[j]*J
        Z[j] += rho_Z[j]*G

    # Partial proof
    proof = Proof()
    proof.J = J
    proof.A = A
    proof.B = B
    proof.C = C
    proof.D = D
    proof.X = X
    proof.Y = Y
    proof.Z = Z

    x = hash_to_scalar(M,P,J,A,B,C,D,X,Y,Z)

    f = [[None for _ in range(n)] for _ in range(m)]
    for j in range(m):
        for i in range(1,n):
            f[j][i] = sigma[j][i]*x + a[j][i]

    zA = rB*x + rA
    zC = rC*x + rD
    zR = r*x**m
    zS = s*x**m
    for j in range(m):
        zR -= rho[j]*x**j
        zS -= rho_Z[j]*x**j

    # Assemble proof
    proof.f = f
    proof.zA = zA
    proof.zC = zC
    proof.zR = zR
    proof.zS = zS

    return proof

# Verify a commitment-to-zero proof
#
# INPUT
#  M: public key list
#  P: value commitment list
#  proof: proof structure
#  m: dimension such that len(M) == len(C) == 2**m
# RETURNS
#  True if the proof is valid
def verify(M,P,proof,m):
    n = 2
    N = n**m

    J = proof.J
    A = proof.A
    B = proof.B
    C = proof.C
    D = proof.D
    X = proof.X
    Y = proof.Y
    Z = proof.Z
    f = proof.f
    zA = proof.zA
    zC = proof.zC
    zR = proof.zR
    zS = proof.zS

    x = hash_to_scalar(M,P,J,A,B,C,D,X,Y,Z)

    for j in range(m):
        f[j][0] = x
        for i in range(1,n):
            f[j][0] -= f[j][i]

    # A/B check
    if not com_matrix(f,zA) == B*x + A:
        raise ArithmeticError('Failed A/B check!')

    # C/D check
    fx = [[None for _ in range(n)] for _ in range(m)]
    for j in range(m):
        for i in range(n):
            fx[j][i] = f[j][i]*(x-f[j][i])
    if not com_matrix(fx,zC) == C*x + D:
        raise ArithmeticError('Failed C/D check!')

    # Commitment check
    R1 = dumb25519.Z
    R2 = dumb25519.Z
    S = dumb25519.Z
    for i in range(N):
        s = Scalar(1)
        decomp_i = decompose(i,n,m)
        for j in range(m):
            s *= f[j][decomp_i[j]]
        R1 += M[i]*s
        R2 += hash_to_point(M[i])*s
        S += P[i]*s
    for j in range(m):
        R1 -= X[j]*x**j
        R2 -= Y[j]*x**j
        S -= Z[j]*x**j
    if not R1 == zR*G or not R2 == zR*J or not S == zS*G:
        raise ArithmeticError('Failed commitment check!')

    return True

# Basic test
m = 3
l = 1

r = random_scalar()
s = random_scalar()

M = [random_point() for _ in range(2**m)]
M[l] = r*G
P = [random_point() for _ in range(2**m)]
P[l] = s*G

proof = prove(M,P,l,r,s,m)
verify(M,P,proof,m)
