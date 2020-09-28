from dumb25519 import Scalar, Point, ScalarVector, PointVector, hash_to_scalar, hash_to_point, random_scalar, Z, G, multiexp
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
    C = Z
    for j in range(len(v)):
        for i in range(len(v[0])):
            C += hash_to_point('Gi',j,i)*v[j][i]
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
    tr = transcript.Transcript('Triptych proof')

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
    X = [Z for _ in range(m)]
    Y = [Z for _ in range(m)]
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

# Verify a batch of commitment-to-zero proofs with common input keys
#
# INPUT
#  M: public key list
#  P: input commitment list
#  proofs: list of proof structures
#  m: dimension such that len(M) = len(P) == 2**m
# RETURNS
#  list of auxiliary data if the proofs are valid
def verify(M,P,proofs,m):
    if not m > 1:
        raise ValueError('Must have m > 1!')

    n = 2
    N = n**m

    # Weighted scalars
    Gi_scalars = [[Scalar(0) for _ in range(n)] for _ in range(m)]
    H_scalar = Scalar(0)
    G_scalar = Scalar(0)
    U_scalar = Scalar(0)
    Mk_scalars = [Scalar(0) for _ in range(N)]
    Pk_scalars = [Scalar(0) for _ in range(N)]

    # Final check
    scalars = ScalarVector([])
    points = PointVector([])

    # Embedded data
    aux = []

    for proof in proofs:
        # Weights
        w1 = Scalar(0)
        w2 = Scalar(0)
        w3 = Scalar(0)
        w4 = Scalar(0)
        while w1 == Scalar(0) or w2 == Scalar(0) or w3 == Scalar(0) or w4 == Scalar(0):
            w1 = random_scalar()
            w2 = random_scalar()
            w3 = random_scalar()
            w4 = random_scalar()

        tr = transcript.Transcript('Triptych proof')

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
        aux1 = None
        aux2 = None
        if seed is not None:
            aux1 = zA - (hash_to_scalar(seed,M,P,J,K,'rB')*x + hash_to_scalar(seed,M,P,J,K,'rA'))
            aux2 = zC - (hash_to_scalar(seed,M,P,J,K,'rC')*x + hash_to_scalar(seed,M,P,J,K,'rD'))
        aux.append([aux1,aux2])

        # Gi
        for j in range(m):
            for i in range(n):
                Gi_scalars[j][i] += w1*f[j][i] + w2*f[j][i]*(x - f[j][i])

        # H
        H_scalar += w1*zA + w2*zC

        # A,B,C,D
        scalars.append(-w1)
        points.append(A)
        scalars.append(-w1*x)
        points.append(B)
        scalars.append(-w2*x)
        points.append(C)
        scalars.append(-w2)
        points.append(D)

        # Initial coefficient product (always zero-index values)
        t = Scalar(1)
        sum_t = Scalar(0)
        for j in range(m):
            t *= f[j][0]
        
        # M,P
        for k,gray_update in enumerate(gray(n,m)):
            # Update the coefficient product
            if k > 0: # we already have the `k=0` value!
                t *= f[gray_update[0]][gray_update[1]].invert()*f[gray_update[0]][gray_update[2]]
            sum_t += t
            Mk_scalars[k] += w3*t
            Pk_scalars[k] += w3*t*mu

        # U,K
        U_scalar += w4*sum_t
        scalars.append(w4*sum_t*mu)
        points.append(K)

        # X,Y
        for j in range(m):
            scalars.append(-w3*x**j)
            points.append(X[j])
            scalars.append(-w4*x**j)
            points.append(Y[j])

        # G,J
        G_scalar -= w3*z
        scalars.append(-w4*z)
        points.append(J)

    # Assemble common points
    for j in range(m):
        for i in range(n):
            scalars.append(Gi_scalars[j][i])
            points.append(hash_to_point('Gi',j,i))
    for k in range(N):
        scalars.append(Mk_scalars[k])
        points.append(M[k])
        scalars.append(Pk_scalars[k])
        points.append(P[k])
    scalars.append(G_scalar)
    points.append(G)
    scalars.append(H_scalar)
    points.append(H)
    scalars.append(U_scalar)
    points.append(U)

    if not multiexp(scalars,points) == Z:
        raise ArithmeticError('Failed verification!')

    return aux
