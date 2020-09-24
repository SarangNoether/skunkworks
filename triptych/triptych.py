# Proof-of-concept implementation of https://github.com/monero-project/research-lab/issues/56

from dumb25519 import hash_to_point, random_scalar, Scalar, hash_to_scalar, G, random_point, Z
import dumb25519
import random
import transcript

H = hash_to_point('H')
U = hash_to_point('U')

# Proof structure
class Proof:
    def __init__(self):
        self.J = None # key image
        self.K = None
        self.A = None
        self.B = None
        self.C = None
        self.D = None
        self.X = None # for signing keys
        self.Y = None # for key image
        self.f = None
        self.zA = None
        self.zC = None
        self.z = None
        self.seed = None

    def __repr__(self):
        temp = '<TriptychProof> '
        temp += 'J:'+repr(self.J)+'|'
        temp += 'K:'+repr(self.K)+'|'
        temp += 'A:'+repr(self.A)+'|'
        temp += 'B:'+repr(self.B)+'|'
        temp += 'C:'+repr(self.C)+'|'
        temp += 'D:'+repr(self.D)+'|'
        temp += 'X:'+repr(self.X)+'|'
        temp += 'Y:'+repr(self.Y)+'|'
        temp += 'f:'+repr(self.f)+'|'
        temp += 'zA:'+repr(self.zA)+'|'
        temp += 'zC:'+repr(self.zC)+'|'
        temp += 'z:'+repr(self.z)
        return temp

# Pedersen matrix commitment
def com_matrix(v,r):
    C = dumb25519.Z
    for i in range(len(v)):
        for j in range(len(v[0])):
            C += hash_to_point('Gi',i,j)*v[i][j]
    C += r*H
    return C

# Generator for Gray codes
# INPUT
#   N: base
#   K number of digits
#   v (optional): if given, the specific value needed
# OUTPUT
#   generator for iterated Gray codes
# NOTES
#   The initial value is always a series of zeros.
#   The generator returns the changed digit, the old value, and the value to which it is changed.
#   To iterate, change the given digit to the given value.
#   This is useful for efficiently computing coefficients during the verification process.
#   If a value is provided, the iterator will only return that value's Gray code (not the changes)
def gray(N,K,v=None):
    g = [0 for _ in range(K+1)]
    u = [1 for _ in range(K+1)]
    changed = [0,0,0] # index, old digit, new digit

    for idx in range(N**K):
        # Standard iterator
        if v is None:
            yield changed
        # Specific value
        else:
            if idx == v:
                yield g[:-1] # return the given Gray code
            if idx > v:
                raise StopIteration # once we have the code, we're done

        i = 0
        k = g[0] + u[0]
        while (k >= N or k < 0):
            u[i] = -u[i]
            i += 1
            k = g[i] + u[i]
        changed = [i,g[i],k]
        g[i] = k

# Kronecker delta
def delta(x,y):
    if x == y:
        return Scalar(1)
    return Scalar(0)

# Compute a convolution with a degree-one polynomial
def convolve(x,y):
    if not len(y) == 2:
        raise ValueError('Convolution requires a degree-one polynomial!')

    r = [Scalar(0)]*(len(x)+1)
    for i in range(len(x)):
        for j in range(len(y)):
            r[i+j] += x[i]*y[j]

    return r

# Perform a commitment-to-zero proof
#
# INPUT
#  M: public key list
#  P: input commitment list
#  l: index such that M[l] and P[l] are commitments to zero
#  r: Pedersen blinder for M[l]
#  s: Pedersen blinder for P[l]
#  m: dimension such that len(M) = len(P) == 2**m
#  seed: seed for data hiding (optional)
#  aux1: auxiliary data to store (optional)
#  aux2: auxiliary data to store (optional)
# RETURNS
#  proof structure
def prove(M,P,l,r,s,m,seed=None,aux1=Scalar(0),aux2=Scalar(0)):
    n = 2 # decomposition base
    tr = transcript.Transcript('Triptych single-input')

    # Commitment list size check
    if not len(M) == n**m or not len(P) == n**m:
        raise IndexError('Input size mismatch!')
    N = len(M)

    # Reconstruct the known commitments
    if not M[l] == r*G or not P[l] == s*G:
        raise ValueError('Bad input commitment!')

    # Construct key image
    J = r.invert()*U
    K = s*J

    # Prepare matrices and corresponding blinders
    rA = random_scalar() if seed is None else hash_to_scalar(seed,M,P,J,K,'rA') + aux1
    rB = random_scalar() if seed is None else hash_to_scalar(seed,M,P,J,K,'rB')
    rC = random_scalar() if seed is None else hash_to_scalar(seed,M,P,J,K,'rC')
    rD = random_scalar() if seed is None else hash_to_scalar(seed,M,P,J,K,'rD') + aux2

    # Commit to zero-sum blinders
    a = [[random_scalar() for _ in range(n)] for _ in range(m)]
    for j in range(m):
        a[j][0] = Scalar(0)
        for i in range(1,n):
            a[j][0] -= a[j][i]
    A = com_matrix(a,rA)

    # Commit to decomposition digits
    decomp_l = next(gray(n,m,l))
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
            a_sq[j][i] = -a[j][i]**2
    D = com_matrix(a_sq,rD)

    # Compute p coefficients
    p = [[] for _ in range(N)]
    decomp_k = [0]*m
    for k,gray_update in enumerate(gray(n,m)):
        decomp_k[gray_update[0]] = gray_update[2]
        p[k] = [a[0][decomp_k[0]],delta(decomp_l[0],decomp_k[0])]
        
        for j in range(1,m):
            p[k] = convolve(p[k],[a[j][decomp_k[j]],delta(decomp_l[j],decomp_k[j])])

    # Generate proof values
    X = [dumb25519.Z for _ in range(m)]
    Y = [dumb25519.Z for _ in range(m)]
    rho = [random_scalar() for _ in range(m)]
    mu = hash_to_scalar(M,P,J,K,A,B,C,D)
    for j in range(m):
        for i in range(N):
            X[j] += (M[i]+mu*P[i])*p[i][j]
            Y[j] += U*p[i][j]
        X[j] += rho[j]*G
        Y[j] += rho[j]*J

    # Partial proof
    proof = Proof()
    proof.J = J
    proof.K = K
    proof.A = A
    proof.B = B
    proof.C = C
    proof.D = D
    proof.X = X
    proof.Y = Y

    # Fiat-Shamir transcript challenge
    tr.update(M)
    tr.update(P)
    tr.update(J)
    tr.update(K)
    tr.update(A)
    tr.update(B)
    tr.update(C)
    tr.update(D)
    tr.update(X)
    tr.update(Y)
    x = tr.challenge()

    # Construct matrix
    f = [[None for _ in range(n-1)] for _ in range(m)]
    for j in range(m):
        for i in range(1,n):
            f[j][i-1] = sigma[j][i]*x + a[j][i]

    zA = rB*x + rA
    zC = rC*x + rD
    z = (r + mu*s)*x**m
    for j in range(m):
        z -= rho[j]*x**j

    # Assemble proof
    proof.f = f
    proof.zA = zA
    proof.zC = zC
    proof.z = z
    proof.seed = seed

    return proof

# Verify a commitment-to-zero proof
#
# INPUT
#  M: public key list
#  P: input commitment list
#  proof: proof structure
#  m: dimension such that len(M) = len(P) == 2**m
# RETURNS
#  auxiliary data if the proof is valid
def verify(M,P,proof,m):
    if not m > 1:
        raise ValueError('Must have m > 1!')

    n = 2
    N = n**m
    tr = transcript.Transcript('Triptych single-input')

    J = proof.J
    K = proof.K
    A = proof.A
    B = proof.B
    C = proof.C
    D = proof.D
    X = proof.X
    Y = proof.Y
    f = [[None for _ in range(n)] for _ in range(m)]
    zA = proof.zA
    zC = proof.zC
    z = proof.z
    seed = proof.seed

    # Fiat-Shamir transcript challenge
    mu = hash_to_scalar(M,P,J,K,A,B,C,D)
    tr.update(M)
    tr.update(P)
    tr.update(J)
    tr.update(K)
    tr.update(A)
    tr.update(B)
    tr.update(C)
    tr.update(D)
    tr.update(X)
    tr.update(Y)
    x = tr.challenge()

    # Reconstruct matrix
    for j in range(m):
        f[j][0] = x
        for i in range(1,n):
            f[j][i] = proof.f[j][i-1]
            f[j][0] -= f[j][i]

    # Recover hidden data if present
    if seed is not None:
        aux1 = zA - (hash_to_scalar(seed,M,P,J,K,'rB')*x + hash_to_scalar(seed,M,P,J,K,'rA'))
        aux2 = zC - (hash_to_scalar(seed,M,P,J,K,'rC')*x + hash_to_scalar(seed,M,P,J,K,'rD'))

    # A/B check
    for j in range(m):
        f[j][0] = x
        for i in range(1,n):
            f[j][0] -= f[j][i]
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
    RX = dumb25519.Z
    RY = dumb25519.Z

    # Initial coefficient product (always zero-index values)
    t = Scalar(1)
    for j in range(m):
        t *= f[j][0]

    for k,gray_update in enumerate(gray(n,m)):
        # Update the coefficient product
        if k > 0: # we already have the `k=0` value!
            t *= f[gray_update[0]][gray_update[1]].invert()*f[gray_update[0]][gray_update[2]]
        RX += (M[k] + mu*P[k])*t
        RY += (U + mu*K)*t

    for j in range(m):
        RX -= X[j]*x**j
        RY -= Y[j]*x**j
    RX -= z*G
    RY -= z*J

    if not RX == dumb25519.Z:
        raise ArithmeticError('Failed signing key check!')
    if not RY == dumb25519.Z:
        raise ArithmeticError('Failed linking check!')

    return aux1,aux2
