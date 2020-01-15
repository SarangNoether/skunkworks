# Hidden timelock
#
# Demonstrates the use of commitment-based timelocks
# - Outputs have associated Pedersen timelock commitments
# - Signers generate range proofs on these commitments
# - They also include extra ring signature data for anonymity
#
# This code is for research purposes only; do not deploy

from dumb25519 import *
import pybullet
import clsag
import random

H = hash_to_point('H')

RING = 4 # ring size
BITS = 4 # range proof bit limit
t_now = Scalar(10) # the current time
l = random.randrange(RING) # signing index

# Generate a ring of outputs
x = random_scalar()
P = PointVector([random_point() for _ in range(RING)])
P[l] = x*G

# Generate a ring of amount commitments
z = random_scalar()
C = PointVector([random_point() for _ in range(RING)])
C[l] = z*G

# Generate a ring of timelock commitments
t_lock = Scalar(3) # time when the output may be spent
w_lock = random_scalar()
W_lock = t_lock*H + w_lock*G
W = PointVector([random_point() for _ in range(RING)])
W[l] = W_lock


# SIGNER
# Has access to `t_lock`, `w_lock`

# Choose a random auxiliary time between the lock time and the current time
# NOTE: it is likely that a uniform selection is suboptimal
if not t_now >= t_lock:
    raise ValueError('Output cannot be spent yet due to timelock!')
t_aux = Scalar(random.randint(t_lock.x,t_now.x))
w_diff = random_scalar()
T_diff = (t_aux - t_lock)*H + w_diff*G

# Build a range proof
print 'Generating range proof...'
proof = pybullet.prove([[t_aux-t_lock,w_diff]],BITS) # using small range for efficiency

# Build a ring signature that includes timelock data
# This ensures we don't leak the secret index `l`
# NOTE: this does not include a proper message
print 'Generating ring signature...'
T = PointVector([W[i] + T_diff - t_aux*H for i in range(RING)])
if not T[l] == (w_lock + w_diff)*G:
    raise ArithmeticError('Bad timelock ring construction!')
sig = clsag.sign('message',x,P,z,C,w_lock + w_diff,T)


# VERIFIER
# Has access to `t_aux`, `T_diff`

# Verify the auxiliary time
if not t_now >= t_aux:
    raise ValueError('Verification error: bad auxiliary time!')

# Verify the range proof
print 'Verifying range proof...'
pybullet.verify([proof],BITS)

# Verify the ring signature
print 'Verifying ring signature...'
clsag.verify('message',P,C,T,sig)
