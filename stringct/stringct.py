# StringCT: a dumb implementation of a sublinear ring signature scheme
#
# Use this code only for prototyping
# -- putting this code into production would be dumb
# -- assuming this code is secure would also be dumb

from dumb25519 import *
import multisig

if not VERSION == 0.2:
    raise Exception('Library version mismatch!')

H = hash_to_point('stringct H')

class SecretKey:
    r = None
    r1 = None

    def __init__(self,r,r1):
        if not isinstance(r,Scalar) or not isinstance(r1,Scalar):
            raise TypeError
        self.r = r
        self.r1 = r1

    def __str__(self):
        return str(self.r)+str(self.r1)

class Output:
    sk = None # secret key
    mask = None # commitment mask
    amount = None # commitment value
    KI = None # key image

    PK = None # public key
    CO = None # commitment
    
    # generate an output to a random stealth address with a given amount
    def gen_random(self,amount):
        if not isinstance(amount,Scalar):
            raise TypeError
        self.amount = amount
        self.mask = random_scalar()
        self.CO = G*amount + H*self.mask
        self.sk = SecretKey(random_scalar(),random_scalar())
        self.KI = G*self.sk.r1
        self.PK = elgamal_commit(self.sk.r1,self.sk.r)

    def __str__(self):
        return str(self.PK)+str(self.CO)

class F:
    KI = None # key image
    PK = None # public key matrix
    CO = None # commitment vector
    CO1 = None # commitment
    m = None # message

    def __init__(self,KI,PK,CO,CO1,m):
        for i in KI:
            if not isinstance(i,Point):
                raise TypeError
        self.KI = KI
        for i in PK:
            for j in i:
                if not len(j) == 2:
                    raise ValueError
                if not isinstance(j[0],Point) or not isinstance(j[1],Point):
                    raise TypeError
        self.PK = PK
        for i in CO:
            if not isinstance(i,Point):
                raise TypeError
        self.CO = CO
        if not isinstance(CO1,Point):
            raise TypeError
        self.CO1 = CO1
        self.m = m

    def __str__(self):
        return str(self.KI) + str(self.PK) + str(self.CO) + str(self.CO1) + str(self.m)

class Proof1:
    A = None
    C = None
    D = None
    f_trim = None
    zA = None
    zC = None
    a = None

    def __init__(self,A,C,D,f_trim,zA,zC,a):
        if not isinstance(A,Point) or not isinstance(C,Point) or not isinstance(D,Point):
            raise TypeError
        self.A = A
        self.C = C
        self.D = D
        for i in f_trim:
            for j in i:
                if not isinstance(j,Scalar):
                    raise TypeError
        self.f_trim = f_trim
        if not isinstance(zA,Scalar) or not isinstance(zC,Scalar):
            raise TypeError
        self.zA = zA
        self.zC = zC
        for i in a:
            for j in i:
                if not isinstance(j,Scalar):
                    raise TypeError
        self.a = a

    def __str__(self):
        return str(self.A)+str(self.C)+str(self.D)+str(self.f_trim)+str(self.zA)+str(self.zC)+str(self.a)

class Proof2:
    proof1 = None
    B = None
    G1 = None
    z = None

    def __init__(self,proof1,B,G1,z):
        if not isinstance(proof1,Proof1):
            raise TypeError
        self.proof1 = proof1
        if not isinstance(B,Point):
            raise TypeError
        self.B = B
        for i in G1:
            if not len(i) == 2:
                raise ValueError
            if not isinstance(i[0],Point) or not isinstance(i[1],Point):
                raise TypeError
        self.G1 = G1
        if not isinstance(z,Scalar):
            raise TypeError
        self.z = z

    def __str__(self):
        return str(self.proof1)+str(self.B)+str(self.G1)+str(self.z)

class SpendInput:
    ii = None
    PK = None
    sk = None
    KI = None
    CO = None
    m = None
    s = None
    base = None
    exponent = None

    def __init__(self):
        pass

class SpendProof:
    base = None
    exponent = None
    CO1 = None
    sigma1 = None
    sigma2 = None

    def __init__(self,base,exponent,CO1,sigma1,sigma2):
        if not isinstance(base,int) or not isinstance(exponent,int):
            raise TypeError
        if base < 2 or exponent < 1:
            raise ValueError
        self.base = base
        self.exponent = exponent
        if not isinstance(CO1,Point):
            raise TypeError
        self.CO1 = CO1
        if not isinstance(sigma1,Proof2):
            raise TypeError
        self.sigma1 = sigma1
        if not isinstance(sigma2,multisig.Multisignature):
            raise TypeError
        self.sigma2 = sigma2

def sub(f_in):
    L = len(f_in.PK) # number of inputs
    N = len(f_in.PK[0]) # ring size
    PKZ = []
    f = []
    for j in range(L):
        PKZ.append([f_in.KI[j],Z])
        f.append(hash_to_scalar(f_in.KI[j],f_in,j))
    C = []
    for i in range(N):
        data0 = [[f_in.CO[i],Scalar(1)]] # multiexp data (first component)
        data1 = [[f_in.CO1,Scalar(1)]] # multiexp data (second component)

        for j in range(L):
            data0.append([f_in.PK[j][i][0],f[j]])
            data0.append([PKZ[j][0],-f[j]])
            data1.append([f_in.PK[j][i][1],f[j]])
            data1.append([PKZ[j][1],-f[j]])

        C.append([multiexp(data0),multiexp(data1)])

    return C,f

# Perform a spend
# INPUT
#   s_in: spend data; type SpendInput
# OUTPUT
#   SpendProof
def spend(s_in):
    if not isinstance(s_in,SpendInput):
        raise TypeError
    s = s_in.s
    CO1 = G*s

    f = F(s_in.KI,s_in.PK,s_in.CO,CO1,s_in.m)
    sub_C,sub_f = sub(f)
    for i in range(len(s_in.sk)):
        s += s_in.sk[i].r*sub_f[i]

    sigma1 = prove2(sub_C,s_in.ii,s,s_in.base,s_in.exponent)

    r1 = [s_in.sk[i].r1 for i in range(len(s_in.sk))]
    sigma2 = multisig.sign(str(sigma1)+str(f),r1)
    
    return SpendProof(s_in.base,s_in.exponent,CO1,sigma1,sigma2)

def prove2(CO,ii,r,base,exponent):
    size = base**exponent
    u = [random_scalar()]*exponent

    ii_seq = decompose(base,ii,exponent)

    d = []
    for j in range(exponent):
        d.append([])
        for i in range(base):
            d[j].append(delta(ii_seq[j],i))

    rB = random_scalar()
    B = matrix_commit(d,rB)

    proof1 = prove1(d,rB)
    coefs = coefficients(proof1.a,ii,ii_seq)

    G1 = []
    for k in range(exponent):
        data0 = [[H,u[k]]]
        data1 = [[G,u[k]]]
        for i in range(size):
            data0.append([CO[i][0],coefs[i][k]])
            data1.append([CO[i][1],coefs[i][k]])
        G1.append([multiexp(data0),multiexp(data1)])

    x = hash_to_scalar(proof1.A,proof1.C,proof1.D)

    z = r*x**exponent
    for i in range(exponent-1,-1,-1):
        z -= u[i]*x**i

    return Proof2(proof1,B,G1,z)

def coefficients(a,ii,ii_seq):
    m = len(a) # exponent
    n = len(a[0]) # base
    size = n**m

    coefs = []
    for k in range(size):
        k_seq = decompose(n,k,m)
        coefs.append([a[0][k_seq[0]],delta(ii_seq[0],k_seq[0])])

        for j in range(1,m):
            coefs[k] = product(coefs[k],[a[j][k_seq[j]],delta(ii_seq[j],k_seq[j])])

    for k in range(size):
        coefs[k] = trim_list(coefs[k],m,m)

    return coefs

def trim_list(a,length,index):
    result = []
    for i in range(len(a)):
        if i < length:
            result.append(a[i])
        else:
            if i == index:
                if a[i] not in [Scalar(0),Scalar(1)]:
                    raise IndexError
            else:
                if a[i] != Scalar(0):
                    raise IndexError

    return result

# Polynomial product coefficients
# INPUT
#   c,d: polynomial coefficients; Scalar lists
# OUTPUT
#   Scalar list
def product(c,d):
    for i in range(len(c)):
        if not isinstance(c[i],Scalar):
            raise TypeError
    for i in range(len(d)):
        if not isinstance(d[i],Scalar):
            raise TypeError

    max_length = max(len(c),len(d))
    result = [Scalar(0)]*(2*max_length-1)

    for i in range(max_length):
        for j in range(max_length):
            if i >= len(c):
                c_i = Scalar(0)
            else:
                c_i = c[i]
            if j >= len(d):
                d_j = Scalar(0)
            else:
                d_j = d[j]
            result[i+j] += c_i*d_j

    return result

def prove1(b,r):
    m = len(b) # exponent
    n = len(b[0]) # base

    a = []
    for j in range(m):
        a.append([Scalar(0)])
        for i in range(1,n):
            a[j].append(random_scalar())
    for j in range(m):
        for i in range(1,n):
            a[j][0] -= a[j][i]

    rA = random_scalar()
    A = matrix_commit(a,rA)

    c = []
    d = []
    for j in range(m):
        c.append([])
        d.append([])
        for i in range(n):
            c[j].append(a[j][i]*(Scalar(1) - b[j][i]*Scalar(2)))
            d[j].append(-(a[j][i]**2))

    rC = random_scalar()
    rD = random_scalar()
    C = matrix_commit(c,rC)
    D = matrix_commit(d,rD)

    x = hash_to_scalar(A,C,D)

    f = []
    for j in range(m):
        f.append([])
        for i in range(n):
            f[j].append(b[j][i]*x+a[j][i])

    f_trim = []
    for j in range(m):
        f_trim.append([])
        for i in range(1,n):
            f_trim[j].append(f[j][i])

    zA = r*x+rA
    zC = rC*x+rD

    return Proof1(A,C,D,f_trim,zA,zC,a)

# Decompose an integer with a given base
# INPUT
#   base: type int
#   n: integer to decompose; type int
#   exponent: maximum length of result; type int
# OUTPUT
#   int list
def decompose(base,n,exponent):
    if not isinstance(base,int) or not isinstance(n,int) or not isinstance(exponent,int):
        raise TypeError
    if base < 2 or n < 0 or exponent < 1:
        raise ValueError

    result = []
    for i in range(exponent-1,-1,-1):
        base_pow = base**i
        result.append(n/base_pow)
        n -= base_pow*result[-1]
    return list(reversed(result))

# Kronecker delta function
# INPUT
#   x,y: any type supporting equality testing
# OUTPUT
#   Scalar: 1 if the inputs are the same, 0 otherwise
def delta(x,y):
    try:
        if x == y:
            return Scalar(1)
        return Scalar(0)
    except:
        raise TypeError

# Scalar matrix commitment
# INPUT
#   m: matrix; list of Scalar lists
#   r: mask; type Scalar
#   raw: whether to return raw multiexp data; True/False
# OUTPUT
#   Point (if raw == False)
#   multiexp data (if raw == True)
def matrix_commit(m,r,raw=False):
    if not isinstance(r,Scalar):
        raise TypeError

    data = [[G,r]] # multiexp data
    for i in range(len(m)):
        for j in range(len(m[0])):
            if not isinstance(m[i][j],Scalar):
                raise TypeError
            data.append([hash_to_point('stringct '+str(i)+' '+str(j)),m[i][j]])

    if not raw:
        return multiexp(data)
    else:
        return data

def verify(KI,PK,CO,CO1,m,sig):
    f = F(KI,PK,CO,CO1,m)
    sub_C,sub_f = sub(f)

    data_multisig = multisig.verify(str(sig.sigma1)+str(f),KI,sig.sigma2,True)
    data_verify2_1 = verify2(sig.base,sig.sigma1,sub_C,True)

    weight1 = random_scalar()
    data = data_multisig[:]
    for i in range(len(data_verify2_1)):
        data.append([data_verify2_1[i][0],weight1*data_verify2_1[i][1]])
    if not multiexp(data) == Z:
        raise ArithmeticError('Failed final check!')

def verify2(base,proof,CO,raw=False):
    data = []
    if not raw:
        verify1(proof.B,proof.proof1)
    else:
        data = verify1(proof.B,proof.proof1,True)

    exponent = len(proof.proof1.f_trim)

    f = []
    for j in range(exponent):
        f.append([Scalar(0)])
        for i in range(1,base):
            f[j].append(proof.proof1.f_trim[j][i-1])

    x = hash_to_scalar(proof.proof1.A,proof.proof1.C,proof.proof1.D)

    for j in range(exponent):
        f[j][0] = x
        for i in range(1,base):
            f[j][0] -= f[j][i]

    g = []
    g.append(f[0][0])
    for j in range(1,exponent):
        g[0] *= f[j][0]

    data0 = [[CO[0][0],g[0]]]
    data1 = [[CO[0][1],g[0]]]
    for i in range(1,base**exponent):
        i_seq = decompose(base,i,exponent)
        g.append(f[0][i_seq[0]])
        for j in range(1,exponent):
            g[i] *= f[j][i_seq[j]]
        data0.append([CO[i][0],g[i]])
        data1.append([CO[i][1],g[i]])

    for k in range(exponent):
        data0.append([proof.G1[k][0],-x**k])
        data1.append([proof.G1[k][1],-x**k])

    data0.append([H,-proof.z])
    data1.append([G,-proof.z])

    # now combine these
    weight0 = random_scalar()
    weight1 = random_scalar()
    for i in range(len(data0)):
        data.append([data0[i][0],weight0*data0[i][1]])
        data.append([data1[i][0],weight1*data1[i][1]])

    if not raw:
        if not [multiexp(data0),multiexp(data1)] == [Z,Z]:
            raise ArithmeticError('Failed verify2!')
    else:
        return data

def verify1(B,proof1,raw=False):
    m = len(proof1.f_trim)
    n = len(proof1.f_trim[0])+1

    f = []
    for j in range(m):
        f.append([Scalar(0)])
        for i in range(1,n):
            f[j].append(proof1.f_trim[j][i-1])

    x = hash_to_scalar(proof1.A,proof1.C,proof1.D)

    for j in range(m):
        f[j][0] = x
        for i in range(1,n):
            f[j][0] -= f[j][i]

    f1 = []
    for j in range(m):
        f1.append([])
        for i in range(n):
            f1[j].append(f[j][i]*(x-f[j][i]))

    for j in range(m):
        col_sum = x
        for i in range(1,n):
            col_sum -= f[j][i]
        if not f[j][0] == col_sum:
            raise ArithmeticError('Failed verify1!')
    
    weight0 = random_scalar()
    weight1 = random_scalar()
    data0 = matrix_commit(f,proof1.zA,True) + [[B,-x],[proof1.A,-Scalar(1)]]
    data1 = matrix_commit(f1,proof1.zC,True) + [[proof1.C,-x],[proof1.D,-Scalar(1)]]
    data = []
    for i in range(len(data0)):
        data.append([data0[i][0],weight0*data0[i][1]])
        data.append([data1[i][0],weight1*data1[i][1]])
    if not raw:
        if not multiexp(data) == Z:
            raise ArithmeticError('Failed verify1!')
    else:
        return data

# Helper functions
def elgamal_encrypt(X,r):
    return [H*r+X,G*r]

def elgamal_commit(x,r):
    return [G*x+H*r,G*r]
