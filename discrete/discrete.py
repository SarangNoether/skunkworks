# Generates and verifies proofs of knowledge of equal discrete logs across groups
# This example uses ed25519 and ed448, but you can substitue your favorite groups
#
# Use this code only for prototyping
# -- putting this code into production would be dumb
# -- assuming this code is secure would also be dumb


import dumb25519
import dumb448

if not dumb25519.VERSION == 0.2 or not dumb448.VERSION == 0.2:
    raise Exception('Library version mismatch!')

max_x = min(dumb25519.l,dumb448.l) # max scalar permitted as discrete log

# Proof structure
class Proof:
    xG = None
    xH = None
    C_G = None
    C_H = None
    e0_G = None
    e0_H = None
    a0 = None
    a1 = None
    b0 = None
    b1 = None

    def __init__(self,xG,xH,C_G,C_H,e0_G,e0_H,a0,a1,b0,b1):
        self.xG = xG
        self.xH = xH
        self.C_G = C_G
        self.C_H = C_H
        self.e0_G = e0_G
        self.e0_H = e0_H
        self.a0 = a0
        self.a1 = a1
        self.b0 = b0
        self.b1 = b1

# Decompose an integer
# INPUT
#   i: value to decompose (int)
#   n: base (int)
#   pad: number of total digits (int)
# OUTPUT
#   array of int digits (lsb is index 0)
def nary(i,n,pad=None):
    if i < 0 or n < 1:
        raise ArithmeticError
    if pad is not None and pad < 1:
        raise IndexError

    if i == 0:
        bits = [0]
    if i > 0:
        bits = []
        while i > 0:
            i,r = divmod(i,n)
            bits.append(r)
    
    if pad is None or pad <= len(bits):
        return bits
    while pad > len(bits):
        bits.append(0)
    return bits

# Generate a proof of knowledge
#
# Assume fixed generators G and H of different groups.
# Let xG and yH be given, where x and y are unknown.
# We want to prove that x = y.
# 
# INPUT
#   x: discrete log (int)
# OUTPUT
#   xG,xH: hash values (Point)
#   C_G,C_H: commitments (PointVector)
#   e0_G,e0_H,a0,a1,b0,b1: proof parameters (ScalarVector)
def prove(x):
    if not x < max_x:
        raise ValueError('Discrete log is too large!')
    if not x >= 0:
        raise ValueError('Discrete log must not be negative!')
    b = nary(x,2)

    # generate blinders that sum to zero
    r = dumb25519.ScalarVector([])
    r_sum = dumb25519.Scalar(0)
    s = dumb448.ScalarVector([])
    s_sum = dumb448.Scalar(0)
    for i in range(len(b)-1):
        r.append(dumb25519.random_scalar())
        r_sum += dumb25519.Scalar(2)**i*r[-1]
        s.append(dumb448.random_scalar())
        s_sum += dumb448.Scalar(2)**i*s[-1]
    temp_2inv_25519 = (dumb25519.Scalar(2)**(len(b)-1)).invert()
    temp_2inv_448 = (dumb448.Scalar(2)**(len(b)-1)).invert()
    r.append(-temp_2inv_25519*r_sum)
    s.append(-temp_2inv_448*s_sum)

    # sanity check on blinder sums
    temp_r = dumb25519.Scalar(0)
    temp_s = dumb448.Scalar(0)
    for i in range(len(b)):
        temp_r += dumb25519.Scalar(2)**i*r[i]
        temp_s += dumb448.Scalar(2)**i*s[i]
    if not temp_r == dumb25519.Scalar(0) or not temp_s == dumb448.Scalar(0):
        raise ArithmeticError('Blinder sum check failed!')

    # generators
    G = dumb25519.G
    G1 = dumb25519.hash_to_point('G1')
    H = dumb448.hash_to_point('H')
    H1 = dumb448.hash_to_point('H1')

    # commitments to bits of x
    C_G = dumb25519.PointVector([])
    C_H = dumb448.PointVector([])
    for i in range(len(b)):
        C_G.append(dumb25519.Scalar(b[i])*G1+r[i]*G)
        C_H.append(dumb448.Scalar(b[i])*H1+s[i]*H)

    # sanity check on commitment sums
    temp_C_G = dumb25519.Z
    temp_C_H = dumb448.Z
    for i in range(len(b)):
        temp_C_G += dumb25519.Scalar(2)**i*C_G[i]
        temp_C_H += dumb448.Scalar(2)**i*C_H[i]
    if not temp_C_G == dumb25519.Scalar(x)*G1 or not temp_C_H == dumb448.Scalar(x)*H1:
        raise ArithmeticError('Bit construction check failed!')

    # proof elements
    e0_G = dumb25519.ScalarVector([])
    e0_H = dumb448.ScalarVector([])
    a0 = dumb25519.ScalarVector([])
    a1 = dumb25519.ScalarVector([])
    b0 = dumb448.ScalarVector([])
    b1 = dumb448.ScalarVector([])

    # construct the proof
    for i in range(len(b)):
        # the current bit is 0
        if b[i] == 0:
            j = dumb25519.random_scalar()
            k = dumb448.random_scalar()
            e1_G = dumb25519.hash_to_scalar(C_G[i],C_H[i],j*G,k*H)
            e1_H = dumb448.hash_to_scalar(C_G[i],C_H[i],j*G,k*H)
            
            a0.append(dumb25519.random_scalar())
            b0.append(dumb448.random_scalar())
            e0_G.append(dumb25519.hash_to_scalar(C_G[i],C_H[i],a0[i]*G-e1_G*(C_G[i]-G1),b0[i]*H-e1_H*(C_H[i]-H1)))
            e0_H.append(dumb448.hash_to_scalar(C_G[i],C_H[i],a0[i]*G-e1_G*(C_G[i]-G1),b0[i]*H-e1_H*(C_H[i]-H1)))

            a1.append(j+e0_G[i]*r[i])
            b1.append(k+e0_H[i]*s[i])
        # the current bit is 1
        elif b[i] == 1:
            j = dumb25519.random_scalar()
            k = dumb448.random_scalar()
            e0_G.append(dumb25519.hash_to_scalar(C_G[i],C_H[i],j*G,k*H))
            e0_H.append(dumb448.hash_to_scalar(C_G[i],C_H[i],j*G,k*H))

            a1.append(dumb25519.random_scalar())
            b1.append(dumb448.random_scalar())
            e1_G = dumb25519.hash_to_scalar(C_G[i],C_H[i],a1[i]*G-e0_G[i]*C_G[i],b1[i]*H-e0_H[i]*C_H[i])
            e1_H = dumb448.hash_to_scalar(C_G[i],C_H[i],a1[i]*G-e0_G[i]*C_G[i],b1[i]*H-e0_H[i]*C_H[i])

            a0.append(j+e1_G*r[i])
            b0.append(k+e1_H*s[i])
        # somehow the bit is something else
        else:
            raise ArithmeticError('Bit decomposition must be 0 or 1!')

    return Proof(dumb25519.Scalar(x)*G1,dumb448.Scalar(x)*H1,C_G,C_H,e0_G,e0_H,a0,a1,b0,b1)

# Verify a proof
# 
# INPUT
#   xG,xH: hash values (Point)
#   C_G,C_H: commitments (PointVector)
#   e0_G,e0_H,a0,a1,b0,b1: proof parameters (ScalarVector)
def verify(proof):
    xG = proof.xG
    xH = proof.xH
    C_G = proof.C_G
    C_H = proof.C_H
    e0_G = proof.e0_G
    e0_H = proof.e0_H
    a0 = proof.a0
    a1 = proof.a1
    b0 = proof.b0
    b1 = proof.b1

    # generators
    G = dumb25519.G
    G1 = dumb25519.hash_to_point('G1')
    H = dumb448.hash_to_point('H')
    H1 = dumb448.hash_to_point('H1')

    # reconstruct hashes using commitments
    xG_prime = dumb25519.Z
    xH_prime = dumb448.Z
    for i in range(len(C_G)):
        xG_prime += dumb25519.Scalar(2)**i*C_G[i]
        xH_prime += dumb448.Scalar(2)**i*C_H[i]
    if not xG_prime == xG or not xH_prime == xH:
        raise ArithmeticError('Commitments do not sum to hash value!')

    for i in range(len(C_G)):
        e1_G = dumb25519.hash_to_scalar(C_G[i],C_H[i],a1[i]*G-e0_G[i]*C_G[i],b1[i]*H-e0_H[i]*C_H[i])
        e1_H = dumb448.hash_to_scalar(C_G[i],C_H[i],a1[i]*G-e0_G[i]*C_G[i],b1[i]*H-e0_H[i]*C_H[i])
        e0_prime_G = dumb25519.hash_to_scalar(C_G[i],C_H[i],a0[i]*G-e1_G*(C_G[i]-G1),b0[i]*H-e1_H*(C_H[i]-H1))
        e0_prime_H = dumb448.hash_to_scalar(C_G[i],C_H[i],a0[i]*G-e1_G*(C_G[i]-G1),b0[i]*H-e1_H*(C_H[i]-H1))
        if not e0_G[i] == e0_prime_G or not e0_H[i] == e0_prime_H:
            raise ArithmeticError('Bitwise ring signature verification failed!')
