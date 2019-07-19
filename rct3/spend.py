# RCT3 spend algorithm

from dumb25519 import *
from random import randrange

RING = 8 # ring size

# Generators
Gc = hash_to_point('Gc')
Hc = hash_to_point('Hc')
U = hash_to_point('U')
G0 = hash_to_point('G0')
Hi = []
for i in range(RING):
    Hi.append(hash_to_point('Hi',i))

k = randrange(RING) # signing index
a = random_scalar() # input value
kappa = random_scalar() # input mask
delta = random_scalar() # input offset

# Set ring and commitments
print 'Preparing ring with',RING,'members...'
pk = []
C_in = []
for i in range(RING):
    pk.append(random_point())
    C_in.append(random_point())

sk = random_scalar() # signing key
pk[k] = sk*G
C_in[k] = a*Hc + kappa*Gc # input commitment
C1 = C_in[k] - delta*Gc # offset commitment

# Key image
U1 = sk.invert()*U

# Final ring
Y = []
temp = repr(pk) + repr(C_in) + repr(C1)
d1 = hash_to_scalar(1,temp)
d2 = hash_to_scalar(2,temp)
for i in range(RING):
    Y.append(pk[i] + d1*(C_in[i]-C1) + d2*G0)

# Check spend index construction
print 'Checking ring...'
assert Y[k] == sk*G + (d1*delta)*Gc + d2*G0

# Prepare signer index
print 'Proving...'
bL = ScalarVector([Scalar(0)]*RING)
bL[k] = Scalar(1)
bR = ScalarVector([])
for i in range(RING):
    bR.append(bL[i] - Scalar(1))

# Point generation
H = hash_to_point(repr(Y))
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
temp = repr(Y) + repr(B) + repr(A) + repr(S1) + repr(S2) + repr(S3) + repr(U1)
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

#
# Verify
#
print 'Verifying...'

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
data.append([H,-tau_x])
data.append([G,z**2 + w*(z-z**2)*(vec_1**vec_y) - z**3*(vec_1**vec_1) - t])
data.append([T1,x])
data.append([T2,x**2])
for i in range(len(data)):
    data[i][1] *= w2
check.extend(data)

# Check 3
data = []
data.append([H,-mu])
data.append([P,-Scalar(1)])
data.append([B,Scalar(1)])
data.append([A,w])
data.append([S2,x])
for i in range(RING):
    data.append([Y[i],-z])
    data.append([Hi[i],(w*z*y**i + z**2)*(y.invert()**i)])
for i in range(len(data)):
    data[i][1] *= w3
check.extend(data)

# Check 4
data = []
data.append([H,z_a])
data.append([G,z_sk])
data.append([Gc,d1*z_d])
data.append([S1,-Scalar(1)])
data.append([B,-x])
data.append([G0,d2*x])
for i in range(len(data)):
    data[i][1] *= w4
check.extend(data)

# Check 5
data = []
data.append([U1,z_sk])
data.append([S3,-Scalar(1)])
data.append([U,-x])
for i in range(len(data)):
    data[i][1] *= w5
check.extend(data)

if not multiexp(check) == Z:
    raise ArithmeticError('Failed verification!')

print 'Success!'
