# Basic transaction flow

from dumb25519 import *
import groth
import pybullet
import schnorr

# Mint a new coin
print 'Minting a new coin...'
v = Scalar(3) # coin value
q = random_scalar()
Q = G*q
s = hash_to_scalar(Q)
r = random_scalar()
C = groth.comm(s,v,r)
mint_proof = schnorr.prove(s,r,groth.G,groth.H2)

# Publicly verify the mint
print 'Verifying mint operation...'
if not mint_proof.Y == C - groth.H1*v or not mint_proof.G == groth.G or not mint_proof.H == groth.H2:
    raise ArithmeticError('Bad Schnorr proof!')
schnorr.verify(mint_proof)

# Generate other fake coins for testing
n = 2
m = 3
Coins = [random_point()]*(n**m)
l = 3 # index of the real coin
Coins[l] = C # the real coin

# Consume the coin and generate 2 new coins
# Generate a spend proof
print 'Generating spend proof...'
M = [coin - groth.comm(s,Scalar(0),Scalar(0)) for coin in Coins]
spend_proof,gammas = groth.prove(M,l,v,r,n,m)

# Publicly verify the spend
print 'Verifying spend proof...'
groth.verify(M,spend_proof,n,m)

# Generate the output coins and range proofs
print 'Generating output range proofs...'
bits = 4
Out1_data = [random_scalar(),Scalar(1),random_scalar()] # s,v,r
Out2_data = [random_scalar(),Scalar(1),random_scalar()] # s,v,r
Out1 = groth.comm(Out1_data[0],Out1_data[1],Out1_data[2])
Out2 = groth.comm(Out2_data[0],Out2_data[1],Out2_data[2])
f = Scalar(1) # fee
range_proof_1 = pybullet.prove([[Out1_data[1],Out1_data[0],Out1_data[2]]],bits)
range_proof_2 = pybullet.prove([[Out2_data[1],Out2_data[0],Out2_data[2]]],bits)

# Publicly verify the range proofs
print 'Verifying range proofs...'
pybullet.verify([range_proof_1,range_proof_2],bits)

# Prove transaction balance
print 'Generating balance proof...'
spend_x = hash_to_scalar(spend_proof.A,spend_proof.B,spend_proof.C,spend_proof.D,spend_proof.G,spend_proof.Q)
balance_x = (Out1_data[0] + Out2_data[0])*spend_x**m
balance_y = (Out1_data[2] + Out2_data[2])*spend_x**m - r*spend_x**m
for j in range(m):
    balance_y -= gammas[j]*spend_x**j
balance_proof = schnorr.prove(balance_x,balance_y,groth.G,groth.H2)

# Publicly verify the balance proof
print 'Verifying balance proof...'
A = (Out1 + Out2 + groth.H1*f)*spend_x**m
B = groth.comm(Scalar(0),spend_proof.zV,spend_proof.zR)
for j in range(m):
    B += spend_proof.Q[j]*spend_x**j

if not balance_proof.Y == A-B or not balance_proof.G == groth.G or not balance_proof.H == groth.H2:
    raise ArithmeticError('Bad balance proof!')
schnorr.verify(balance_proof)
