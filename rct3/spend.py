from dumb25519 import *
from common import *

# Spend proof
class SpendProof:
    def __init__(self):
        self.A = None
        self.B = None
        self.S1 = None
        self.S2 = None
        self.S3 = None
        self.T1 = None
        self.T2 = None
        self.tau_x = None
        self.mu = None
        self.z_a = None
        self.z_sk = None
        self.z_d = None
        self.l = None
        self.r = None
        self.t = None
        self.P = None
        self.U1 = None

# Generate a spend proof
#
# INPUTS
#   pk: list of public keys (Points)
#   C_in: list of corresponding input commitments (Points)
#   k: signing index (int)
#   a: input amount (Scalar)
#   kappa: input mask (Scalar)
#   delta: input offset (Scalar)
#   sk: secret key (Scalar)
# OUTPUTS
#   proof: spend proof
def prove(pk,C_in,k,a,kappa,delta,sk):
    # Sanity checks
    if not len(pk) == RING or not len(C_in) == RING:
        raise IndexError('Bad input ring size!')

    # Key image
    U1 = sk.invert()*U

    # Offset commitment
    C1 = C_in[k] - delta*Gc # offset commitment

    # Construct ring
    Y = []
    temp = repr(pk) + repr(C_in) + repr(C1)
    d1 = hash_to_scalar(1,temp)
    d2 = hash_to_scalar(2,temp)
    for i in range(RING):
        Y.append(pk[i] + d1*(C_in[i]-C1) + d2*G0)

    # Confirm true spend
    if not Y[k] == sk*G + (d1*delta)*Gc + d2*G0:
        raise ValueError('Invalid signer public key!')

    # Prepare signer index
    bL = ScalarVector([Scalar(0)]*RING)
    bL[k] = Scalar(1)
    bR = ScalarVector([])
    for i in range(RING):
        bR.append(bL[i] - Scalar(1))

    # Point generation
    H = hash_to_point(repr(pk) + repr(C_in) + repr(C1))
    alpha = random_scalar()
    beta = random_scalar()
    p = random_scalar()
    r_a = random_scalar()
    r_sk = random_scalar()
    r_d = random_scalar()
    sL = ScalarVector([])
    sR = ScalarVector([])
    for i in range(RING):
        sL.append(random_scalar())
        sR.append(random_scalar())

    # Commit 1
    B = alpha*H
    A = beta*H
    for i in range(RING):
        B += bL[i]*Y[i]
        A += bR[i]*Hi[i]
    S1 = r_a*H + r_sk*G + (d1*r_d)*Gc
    S2 = p*H
    for i in range(RING):
        S2 += sL[i]*Y[i] + sR[i]*Hi[i]
    S3 = r_sk*U1

    # Challenge 1
    temp = repr(pk) + repr(C_in) + repr(C1) + repr(B) + repr(A) + repr(S1) + repr(S2) + repr(S3) + repr(U1)
    y = hash_to_scalar(1,temp)
    z = hash_to_scalar(2,temp)
    w = hash_to_scalar(3,temp)

    # Commit 2
    vec_1 = ScalarVector([Scalar(1)]*RING)

    l0 = bL - ScalarVector([z]*RING)
    l1 = sL

    vec_y = ScalarVector([y**i for i in range(RING)])
    r0 = vec_y*(bR*w + ScalarVector([w*z]*RING)) + ScalarVector([z**2]*RING)
    r1 = vec_y*sR

    t1 = l0**r1 + l1**r0
    t2 = l1**r1
    tau1 = random_scalar()
    tau2 = random_scalar()
    T1 = t1*G + tau1*H
    T2 = t2*G + tau2*H

    # Challenge 2
    temp = repr(w) + repr(y) + repr(z) + repr(T1) + repr(T2)
    x = hash_to_scalar(temp)

    # Response
    l = l0 + l1*x
    r = r0 + r1*x
    t = l**r
    P = Z
    for i in range(RING):
        P += l[i]*Y[i] + (y.invert()**i*r[i])*Hi[i]
    tau_x = tau1*x + tau2*(x**2)
    mu = alpha + beta*w + p*x
    z_a = r_a + alpha*x
    z_sk = r_sk + sk*x
    z_d = r_d + delta*x

    # Construct proof
    proof = SpendProof()
    proof.A = A
    proof.B = B
    proof.S1 = S1
    proof.S2 = S2
    proof.S3 = S3
    proof.T1 = T1
    proof.T2 = T2
    proof.tau_x = tau_x
    proof.mu = mu
    proof.z_a = z_a
    proof.z_sk = z_sk
    proof.z_d = z_d
    proof.l = l
    proof.r = r
    proof.t = t
    proof.P = P
    proof.U1 = U1
    return proof

# Verify a spend proof
#
# INPUTS
#   proof: spend proof (SpendProof)
#   pk: list of public keys (Points)
#   C_in: list of corresponding input commitments (Points)
#   C1: commitment offset (Point)
def verify(proof,pk,C_in,C1):
    # Construct ring
    temp = repr(pk) + repr(C_in) + repr(C1)
    d1 = hash_to_scalar(1,temp)
    d2 = hash_to_scalar(2,temp)

    # Construct challenges
    temp = repr(pk) + repr(C_in) + repr(C1) + repr(proof.B) + repr(proof.A) + repr(proof.S1) + repr(proof.S2) + repr(proof.S3) + repr(proof.U1)
    y = hash_to_scalar(1,temp)
    z = hash_to_scalar(2,temp)
    w = hash_to_scalar(3,temp)

    temp = repr(w) + repr(y) + repr(z) + repr(proof.T1) + repr(proof.T2)
    x = hash_to_scalar(temp)

    # Useful values
    H = hash_to_point(repr(pk) + repr(C_in) + repr(C1))
    vec_1 = ScalarVector([Scalar(1)]*RING)
    vec_y = ScalarVector([y**i for i in range(RING)])

    check = [] # the final multiexp data

    # Generate nonzero random weights (indexed by equation number)
    w2 = Scalar(0)
    while w2 == Scalar(0):
        w2 = random_scalar()
    w3 = Scalar(0)
    while w3 == Scalar(0):
        w3 = random_scalar()
    w4 = Scalar(0)
    while w4 == Scalar(0):
        w4 = random_scalar()
    w5 = Scalar(0)
    while w5 == Scalar(0):
        w5 = random_scalar()

    # Check 2
    data = []
    data.append([H,-proof.tau_x])
    data.append([G,z**2 + w*(z-z**2)*(vec_1**vec_y) - z**3*(vec_1**vec_1) - proof.t])
    data.append([proof.T1,x])
    data.append([proof.T2,x**2])
    for i in range(len(data)):
        data[i][1] *= w2
    check.extend(data)

    # Check 3
    data = []
    data.append([H,-proof.mu])
    data.append([proof.P,-Scalar(1)])
    data.append([proof.B,Scalar(1)])
    data.append([proof.A,w])
    data.append([proof.S2,x])
    for i in range(RING):
        data.append([pk[i],-z])
        data.append([C_in[i],-z*d1])
        data.append([C1,z*d1])
        data.append([G0,-z*d2])
        data.append([Hi[i],(w*z*y**i + z**2)*(y.invert()**i)])
    for i in range(len(data)):
        data[i][1] *= w3
    check.extend(data)

    # Check 4
    data = []
    data.append([H,proof.z_a])
    data.append([G,proof.z_sk])
    data.append([Gc,d1*proof.z_d])
    data.append([proof.S1,-Scalar(1)])
    data.append([proof.B,-x])
    data.append([G0,d2*x])
    for i in range(len(data)):
        data[i][1] *= w4
    check.extend(data)

    # Check 5
    data = []
    data.append([proof.U1,proof.z_sk])
    data.append([proof.S3,-Scalar(1)])
    data.append([U,-x])
    for i in range(len(data)):
        data[i][1] *= w5
    check.extend(data)

    if not multiexp(check) == Z:
        raise ArithmeticError('Failed verification!')
