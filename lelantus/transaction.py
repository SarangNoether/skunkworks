# Basic transaction flow

from common import *
from dumb25519 import *
import groth
import pybullet
import schnorr
import elgamal
import signature
import random

# The result of a mint operation
class MintTransaction:
    # Public values
    Y = None # coin public key
    C = None # coin commitment
    v = None # coin value
    proof = None # Schnorr proof
    enc_r = None # encrypted coin blinder
    enc_y = None # encrypted partial Diffie-Hellman secret

    # Mint the coin
    #
    # INPUTS
    #   v: coin value
    #   P: destination address
    def __init__(self,v,P):
        y = random_scalar()
        s = hash_to_scalar(P*y) # coin serial number
        r = random_scalar()
        C = groth.comm(s,v,r)
        proof = schnorr.prove(s,r,G,H2)

        self.Y = G*y
        self.C = C
        self.proof = proof
        self.v = v
        self.enc_r = elgamal.encrypt(r,P)
        self.enc_y = elgamal.encrypt(y,P)
        self.P = P

    # Verify the mint
    def verify(self):
        if not self.proof.W == G or not self.proof.X == H2:
            raise ValueError('Mint proof contains bad generators!')
        if not self.proof.Y == self.C - H1*self.v:
            raise ValueError('Mint proof contains bad point!')
        schnorr.verify(self.proof)

# The result of a spend operation
class SpendTransaction:
    # Public values
    C_list = None # anonymity set
    n = None
    m = None
    Q = [] # input coin public keys
    spend_proofs = [] # spend proofs
    spend_sigs = [] # spend proof signatures
    C = [] # output coin commitments
    f = None # fee
    range_proof = None # aggregated range proof
    balance_proof = None # balance proof
    enc_r = [] # encrypted coin blinders
    enc_v = [] # encrypted coin values
    enc_y = [] # encrypted partial Diffie-Hellman secrets

    # Initiate the spend operation
    #
    # INPUTS
    #   C_list: anonymity set (list)
    #   n,m: len(C_list) = n**m
    #   q: input coin private keys (list)
    #   l: indices in anonymity set (list)
    #   v_in: input coin values (list)
    #   r_in: input coin blinders (list)
    #   v_out: output coin values (list)
    #   f: fee
    #   P: destination addresses (list)
    def __init__(self,C_list,n,m,q,l,v_in,r_in,v_out,f,P):
        # NOTE: This only supports spending a single input
        # This is because of aggregate Fiat-Shamir limitations in the Groth proving system
        if not len(q) == 1:
            raise ValueError('Only single spends are supported!')

        # Confirm balance
        balance = Scalar(0)
        for i in v_in:
            balance += i
        for i in v_out:
            balance -= i
        balance -= f
        if not balance == Scalar(0):
            raise ArithmeticError('Spend transaction does not balance!')
        
        # Generate spend proofs and signatures
        spend_gammas = []
        for i in range(len(q)):
            # Spend proof
            self.Q.append(G*q[i])
            s = hash_to_scalar(self.Q[-1])
            if not C_list[l[i]] == groth.comm(s,v_in[i],r_in[i]):
                raise ValueError('Coin commitment does not match private data!')
            offset = groth.comm(s,Scalar(0),Scalar(0))
            M = [C-offset for C in C_list] # one is a commitment to zero
            spend_proof,gammas = groth.prove(M,l[i],v_in[i],r_in[i],n,m)
            self.spend_proofs.append(spend_proof)
            spend_gammas.append(gammas)

            # Spend proof signature
            self.spend_sigs.append(signature.sign(repr(spend_proof),q[i]))

        # Store input anonymity set and fee
        self.C_list = C_list
        self.f = f
        self.n = n
        self.m = m

        # Generate outputs
        range_proof_data = [] # for aggregate range proof
        for i in range(len(v_out)):
            y = random_scalar()
            s = hash_to_scalar(P[i]*y) # coin serial number
            r_out = random_scalar()
            self.C.append(groth.comm(s,v_out[i],r_out)) # new output coin
            range_proof_data.append([s,v_out[i],r_out])

            # Encrypt data for recipients
            self.enc_r = elgamal.encrypt(r_out,P[i])
            self.enc_v = elgamal.encrypt(v_out[i],P[i])
            self.enc_y = elgamal.encrypt(y,P[i])

        # Aggregate range proof
        self.range_proof = pybullet.prove(range_proof_data,BITS)

        # Balance proof
        spend_proof = self.spend_proofs[0]
        spend_x = hash_to_scalar(spend_proof.A,spend_proof.B,spend_proof.C,spend_proof.D,spend_proof.G,spend_proof.Q)
        balance_x = Scalar(0)
        balance_y = Scalar(0)
        for i in range(len(v_out)):
            balance_x += range_proof_data[i][0]
            balance_y += range_proof_data[i][2]
        balance_x *= spend_x**m
        balance_y *= spend_x**m
        balance_y -= r_in[0]*spend_x**m

        for j in range(m):
            balance_y -= spend_gammas[0][j]*spend_x**j
        balance_proof = schnorr.prove(balance_x,balance_y,G,H2)

        self.balance_proof = balance_proof

    # Verify the spend
    def verify(self):
        # Verify the spend proof signatures
        for i in range(len(self.spend_sigs)):
            signature.verify(repr(self.spend_proofs[i]),self.Q[i],self.spend_sigs[i])

        # Verify the spend proofs
        for i in range(len(self.spend_proofs)):
            s = hash_to_scalar(self.Q[i])
            offset = groth.comm(s,Scalar(0),Scalar(0))
            M = [C-offset for C in self.C_list]
            groth.verify(M,self.spend_proofs[i],n,m)

        # Verify the aggregate range proof
        pybullet.verify([self.range_proof],BITS)

        # Verify the balance proof
        spend_proof = self.spend_proofs[0]
        spend_x = hash_to_scalar(spend_proof.A,spend_proof.B,spend_proof.C,spend_proof.D,spend_proof.G,spend_proof.Q)

        A = H1*self.f
        for i in range(len(self.C)):
            A += self.C[i]
        A *= spend_x**self.m
        B = groth.comm(Scalar(0),self.spend_proofs[0].zV,self.spend_proofs[0].zR)
        for j in range(m):
            B += self.spend_proofs[0].Q[j]*spend_x**j

        if not self.balance_proof.Y == A-B or not self.balance_proof.W == G or not self.balance_proof.X == H2:
            raise ArithmeticError('Bad balance proof!')
        schnorr.verify(self.balance_proof)

# Alice's keys
a = random_scalar()
A = G*a

# Bob's keys
b = random_scalar()
B = G*b

# Mint a new coin to Alice and publicly verify
print 'Minting a new coin to Alice...'
mint = MintTransaction(Scalar(3),A)
print 'Verifying...'
mint.verify()

# Generate other fake coins for testing
n = 2
m = 3
Coins = [random_point()]*(n**m)
l = random.randrange(len(Coins)) # index of the real coin
Coins[l] = mint.C # the real coin

# Alice recovers the coin blinder and private key
r = elgamal.decrypt(mint.enc_r,a)
y = elgamal.decrypt(mint.enc_y,a)

# Alice spends her coin to Bob with change to herself
# Consume the coin and generate 2 new coins
# Generate a spend proof and publicly verify
print 'Generating spend proof...'
spend = SpendTransaction(Coins,n,m,[a*y],[l],[mint.v],[r],[Scalar(1),Scalar(1)],Scalar(1),[B,A])
print 'Verifying...'
spend.verify()
