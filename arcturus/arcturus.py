# Proof-of-concept implementation of https://github.com/monero-project/research-lab/issues/56

from dumb25519 import hash_to_point, random_scalar, Scalar, hash_to_scalar, G, random_point, Z
from dumb25519 import ScalarVector, PointVector
import dumb25519
import random
import transcript

H = hash_to_point('H')
U = hash_to_point('U')

# Proof structure
class Proof:
    def __init__(self):
        self.J = None # key images
        self.A = None
        self.B = None
        self.C = None
        self.D = None
        self.X = None # for signing keys
        self.Y = None # for key images
        self.Z = None # for amounts
        self.f = None
        self.zA = None
        self.zC = None
        self.zR = None # for signing keys and key images
        self.zS = None # for amounts
        self.seed = None

    def __repr__(self):
        temp = '<ArcturusProof> '
        temp += 'J:'+repr(self.J)+'|'
        temp += 'A:'+repr(self.A)+'|'
        temp += 'B:'+repr(self.B)+'|'
        temp += 'C:'+repr(self.C)+'|'
        temp += 'D:'+repr(self.D)+'|'
        temp += 'X:'+repr(self.X)+'|'
        temp += 'Y:'+repr(self.Y)+'|'
        temp += 'Z:'+repr(self.Z)+'|'
        temp += 'f:'+repr(self.f)+'|'
        temp += 'zA:'+repr(self.zA)+'|'
        temp += 'zC:'+repr(self.zC)+'|'
        temp += 'zR:'+repr(self.zR)+'|'
        temp += 'zS:'+repr(self.zS)
        return temp

# Pedersen tensor commitment
def com_tensor(v,r):
    C = dumb25519.Z
    for i in range(len(v)):
        for j in range(len(v[0])):
            for k in range(len(v[0][0])):
                C += hash_to_point('Gi',i,j,k)*v[i][j][k]
    C += r*H
    return C

# Generator for Gray codes
# INPUT
#   N: base
#   K: number of digits
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

# Perform a multi-index commitment-to-zero proof
#
# INPUT
#  M: public key list
#  P: input commitment list
#  Q: output commitment list
#  l: list of indices such that each M[l[u]] is a commitment to zero
#  r: list of Pedersen blinders for all M[l[u]]
#  s: list of Pedersen blinders for all P[l[u]]
#  t: list of Pedersen blinders for all Q[j]
#  a: list of Pedersen values for all P[l[u]]
#  b: list of Pedersen values for all Q[j]
#  m: dimension such that len(M) == 2**m
#  seed: seed for data hiding (optional)
#  aux1: auxiliary data to store (optional)
#  aux2: auxiliary data to store (optional)
# RETURNS
#  proof structure
def prove(M,P,Q,l,r,s,t,a,b,m,seed=None,aux1=Scalar(0),aux2=Scalar(0)):
    n = 2 # decomposition base
    tr = transcript.Transcript('Arcturus')

    # Commitment list size check
    if not len(M) == n**m or not len(P) == n**m:
        raise IndexError('Input size mismatch!')
    if not len(l) == len(r) or not len(l) == len(s) or not len(l) == len(a):
        raise IndexError('Input size mismatch!')
    if not len(Q) == len(t) or not len(Q) == len(b):
        raise IndexError('Output size mismatch!')
    N = len(M)

    # Reconstruct the known commitments
    w = len(l)
    for u in range(w):
        if not M[l[u]] == r[u]*G or not P[l[u]] == s[u]*G + a[u]*H:
            raise ValueError('Bad input commitment!')
    for j in range(len(Q)):
        if not Q[j] == t[j]*G + b[j]*H:
            raise ValueError('Bad output commitment!')

    # Construct key images
    J = []
    for u in range(w):
        J.append(r[u].invert()*U)

    # Prepare matrices and corresponding blinders
    rA = random_scalar() if seed is None else hash_to_scalar(seed,M,P,Q,J,'rA') + aux1
    rB = random_scalar() if seed is None else hash_to_scalar(seed,M,P,Q,J,'rB')
    rC = random_scalar() if seed is None else hash_to_scalar(seed,M,P,Q,J,'rC')
    rD = random_scalar() if seed is None else hash_to_scalar(seed,M,P,Q,J,'rD') + aux2

    # Commit to zero-sum blinders
    a = [[[random_scalar() for _ in range(n)] for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for u in range(w):
            a[u][j][0] = Scalar(0)
            for i in range(1,n):
                a[u][j][0] -= a[u][j][i]
    A = com_tensor(a,rA)

    # Commit to decomposition digits
    decomp_l = []
    for u in range(w):
        decomp_l.append(next(gray(n,m,l[u])))
    sigma = [[[None for _ in range(n)] for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for i in range(n):
            for u in range(w):
                sigma[u][j][i] = delta(decomp_l[u][j],i)
    B = com_tensor(sigma,rB)

    # Commit to a/sigma relationships
    a_sigma = [[[Scalar(0) for _ in range(n)] for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for i in range(n):
            for u in range(w):
                a_sigma[u][j][i] = a[u][j][i]*(Scalar(1) - Scalar(2)*sigma[u][j][i])
    C = com_tensor(a_sigma,rC)
    
    # Commit to squared a-values
    a_sq = [[[Scalar(0) for _ in range(n)] for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for i in range(n):
            for u in range(w):
                a_sq[u][j][i] = -a[u][j][i]**2
    D = com_tensor(a_sq,rD)

    # Compute p coefficients
    p = [[[] for _ in range(N)] for _ in range(w)]
    decomp_k = [0]*m
    for k,gray_update in enumerate(gray(n,m)):
        decomp_k[gray_update[0]] = gray_update[2]
        for u in range(w):
            p[u][k] = [a[u][0][decomp_k[0]],delta(decomp_l[u][0],decomp_k[0])]
        
        for j in range(1,m):
            for u in range(w):
                p[u][k] = convolve(p[u][k],[a[u][j][decomp_k[j]],delta(decomp_l[u][j],decomp_k[j])])

        # Combine to single coefficients in p[0]
        for j in range(m):
            for u in range(1,w):
                p[0][k][j] += p[u][k][j]

    # Generate proof values
    X = [dumb25519.Z for _ in range(m)]
    Y = [dumb25519.Z for _ in range(m)]
    Z = [dumb25519.Z for _ in range(m)]
    mu = hash_to_scalar('Arcturus mu',M,P,Q,J,A,B,C,D)
    rho_R = [[random_scalar() for _ in range(m)] for _ in range(w)]
    rho_S = [[random_scalar() for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for i in range(N):
            X[j] += M[i]*p[0][i][j]*mu**i
            Y[j] += U*p[0][i][j]*mu**i
            Z[j] += P[i]*p[0][i][j]
        for u in range(w):
            X[j] += rho_R[u][j]*G
            Y[j] += rho_R[u][j]*J[u]
            Z[j] += rho_S[u][j]*G

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

    # Fiat-Shamir transcript challenge
    tr.update(M)
    tr.update(P)
    tr.update(Q)
    tr.update(J)
    tr.update(A)
    tr.update(B)
    tr.update(C)
    tr.update(D)
    tr.update(X)
    tr.update(Y)
    tr.update(Z)
    x = tr.challenge()

    # Construct matrix
    f = [[[None for _ in range(n-1)] for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for i in range(1,n):
            for u in range(w):
                f[u][j][i-1] = sigma[u][j][i]*x + a[u][j][i]

    zA = rB*x + rA
    zC = rC*x + rD
    zR = []
    zS = Scalar(0)
    for u in range(w):
        zR.append(mu**l[u]*r[u]*x**m)
        zS += s[u]*x**m
    for j in range(m):
        for u in range(w):
            zR[u] -= rho_R[u][j]*x**j
            zS -= rho_S[u][j]*x**j
    for i in range(len(t)):
        zS -= t[i]*x**m

    # Assemble proof
    proof.f = f
    proof.zA = zA
    proof.zC = zC
    proof.zR = zR
    proof.zS = zS
    proof.seed = seed

    return proof

# Verify a commitment-to-zero proof
#
# INPUT
#  M: public key list
#  P: input commitment list
#  Q: output commitment list
#  proof: proof structure
#  m: dimension such that len(M) == 2**m
# RETURNS
#  auxiliary data if the proof is valid
def verify(M,P,Q,proof,m):
    if not m > 1:
        raise ValueError('Must have m > 1!')

    n = 2
    N = n**m
    tr = transcript.Transcript('Arcturus')

    J = proof.J
    w = len(J)
    A = proof.A
    B = proof.B
    C = proof.C
    D = proof.D
    X = proof.X
    Y = proof.Y
    Z = proof.Z
    f = [[[None for _ in range(n)] for _ in range(m)] for _ in range(w)]
    zA = proof.zA
    zC = proof.zC
    zR = proof.zR
    zS = proof.zS
    seed = proof.seed

    # Fiat-Shamir transcript challenge
    tr.update(M)
    tr.update(P)
    tr.update(Q)
    tr.update(J)
    tr.update(A)
    tr.update(B)
    tr.update(C)
    tr.update(D)
    tr.update(X)
    tr.update(Y)
    tr.update(Z)
    x = tr.challenge()

    # Random weights for verification
    w1 = Scalar(0)
    w2 = Scalar(0)
    w3 = Scalar(0)
    w4 = Scalar(0)
    w5 = Scalar(0)
    while (w1 == Scalar(0) or w2 == Scalar(0) or w3 == Scalar(0) or w4 == Scalar(0) or w5 == Scalar(0)):
        w1 = random_scalar()
        w2 = random_scalar()
        w3 = random_scalar()
        w4 = random_scalar()
        w5 = random_scalar()

    scalars = ScalarVector([])
    points = PointVector([])

    # Recover hidden data if present
    if seed is not None:
        aux1 = zA - (hash_to_scalar(seed,M,P,Q,J,'rB')*x + hash_to_scalar(seed,M,P,Q,J,'rA'))
        aux2 = zC - (hash_to_scalar(seed,M,P,Q,J,'rC')*x + hash_to_scalar(seed,M,P,Q,J,'rD'))

    # Reconstruct tensors
    for j in range(m):
        for u in range(w):
            f[u][j][0] = x
        for i in range(1,n):
            for u in range(w):
                f[u][j][i] = proof.f[u][j][i-1]
                f[u][j][0] -= f[u][j][i]

    fx = [[[None for _ in range(n)] for _ in range(m)] for _ in range(w)]
    for j in range(m):
        for i in range(n):
            for u in range(w):
                fx[u][j][i] = f[u][j][i]*(x-f[u][j][i])

    # Gi, H
    for j in range(m):
        for i in range(n):
            for u in range(w):
                scalars.append(w1*f[u][j][i] + w2*fx[u][j][i])
                points.append(hash_to_point('Gi',u,j,i))
    scalars.append(w1*zA + w2*zC)
    points.append(H)

    # A, B, C, D
    scalars.append(-w1)
    points.append(A)
    scalars.append(-w1*x)
    points.append(B)
    scalars.append(-w2*x)
    points.append(C)
    scalars.append(-w2)
    points.append(D)

    # M, P, U
    U_scalar = Scalar(0)
    mu = hash_to_scalar('Arcturus mu',M,P,Q,J,A,B,C,D)

    # Initial coefficient product (always zero-index values)
    t = [Scalar(1) for _ in range(w)]
    for j in range(m):
        for u in range(w):
            t[u] *= f[u][j][0]

    for k,gray_update in enumerate(gray(n,m)):
        # Update the coefficient product
        if k > 0: # we already have the `k=0` value!
            for u in range(w):
                t[u] *= f[u][gray_update[0]][gray_update[1]].invert()*f[u][gray_update[0]][gray_update[2]]
        sum_t = Scalar(0)
        for u in range(w):
            sum_t += t[u]
        scalars.append(w3*sum_t*mu**k)
        points.append(M[k])
        scalars.append(w5*sum_t)
        points.append(P[k])
        U_scalar += w4*sum_t*mu**k
    scalars.append(U_scalar)
    points.append(U)

    # X, Y, Z
    for j in range(m):
        scalars.append(-w3*x**j)
        points.append(X[j])
        scalars.append(-w4*x**j)
        points.append(Y[j])
        scalars.append(-w5*x**j)
        points.append(Z[j])

    # G, J
    G_scalar = Scalar(0)
    for u in range(w):
        G_scalar += zR[u]
        scalars.append(-w4*zR[u])
        points.append(J[u])
    scalars.append(-w3*G_scalar - w5*zS)
    points.append(G)

    # Q
    for j in range(len(Q)):
        scalars.append(-w5*x**m)
        points.append(Q[j])

    if not dumb25519.multiexp(scalars,points) == dumb25519.Z:
        raise ArithmeticError('Failed verification!')

    return aux1,aux2
