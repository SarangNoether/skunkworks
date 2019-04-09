# Basic transaction flow

from dumb25519 import *
import groth
import pybullet
import schnorr

# Mint a new coin
print 'Minting a new coin...'
v = Scalar(2)
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
spend_proof = groth.prove(M,l,v,r,n,m)

# Publicly verify the spend
print 'Verifying spend proof...'
groth.verify(M,spend_proof,n,m)

# Generate the output coins and range proofs
print 'Generating output range proofs...'
bits = 4
Out1_data = [Scalar(1),random_scalar(),random_scalar()] # v, s, r
Out2_data = [Scalar(1),random_scalar(),random_scalar()] # v, s, r
Out1 = groth.comm(Out1_data[1],Out1_data[0],Out1_data[2])
Out2 = groth.comm(Out2_data[1],Out2_data[0],Out2_data[2])
range_proof_1 = pybullet.prove([Out1_data],bits)
range_proof_2 = pybullet.prove([Out2_data],bits)

# Publicly verify the range proofs
print 'Verifying range proofs...'
pybullet.verify([range_proof_1,range_proof_2],bits)
