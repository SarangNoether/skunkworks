# Basic transaction flow

from common import *
from dumb25519 import *
import groth
import pybullet
import schnorr
import elgamal
import signature
import random
import clsag

# The result of a migration operation
class MigrationTransaction:
    # Migrate an existing coin
    #
    # INPUTS
    #   P_in: public key anonymity set (list)
    #   C_in: commitment anonymity set (list)
    #   l: private key index
    #   p: private key
    #   v: commitment value
    #   a: commitment mask
    #   f: fee
    #   P: destination address
    def __init__(self,P_in,C_in,l,p,v,a,f,P):
        y = random_scalar()
        s = hash_to_scalar(P*y) # coin serial number

        # Ensure commitment data is valid
        if not com(v,a) == C_in[l]:
            raise ArithmeticError('Bad known commitment!')

        # Offset commitments using intermediate commitment
        b = random_scalar()
        C1 = com(v,b)
        for i in range(len(C_in)):
            C_in[i] -= C1

        # Generate CLSAG signature
        sig = clsag.sign('test',p,P_in,a-b,C_in)

        # Generate Lelantus commitment
        r = random_scalar()
        D = groth.comm(s,v-f,r)

        # Prove value balance
        proof = schnorr.prove(r-b,s,H2,G)

        # Encrypt recipient data
        enc_r = elgamal.encrypt(r,P)
        enc_v = elgamal.encrypt(v-f,P)
        enc_y = elgamal.encrypt(y,P)
        
        self.P_in = P_in
        self.C_in = C_in
        self.Y = G*y
        self.C1 = C1
        self.sig = sig
        self.D = D
        self.proof = proof
        self.enc_r = enc_r
        self.enc_v = enc_v
        self.enc_y = enc_y
        self.f = f

    # Verify the migration
    def verify(self):
        # Verify CLSAG signature
        clsag.verify('test',self.P_in,self.C_in,self.sig)

        # Verify balance
        if not self.proof.W == H2 or not self.proof.X == G:
            raise ValueError('Migration proof contains bad generators!')
        if not self.proof.Y == self.D + H1*self.f - self.C1:
            raise ValueError('Migration proof contains bad point!')
        schnorr.verify(self.proof)

# The result of a mint operation
class MintTransaction:
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
        self.v = v
        self.proof = proof
        self.enc_r = elgamal.encrypt(r,P)
        self.enc_y = elgamal.encrypt(y,P)

    # Verify the mint
    def verify(self):
        if not self.proof.W == G or not self.proof.X == H2:
            raise ValueError('Mint proof contains bad generators!')
        if not self.proof.Y == self.C - H1*self.v:
            raise ValueError('Mint proof contains bad point!')
        schnorr.verify(self.proof)

# The result of a spend operation
class SpendTransaction:
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
        # Confirm balance
        balance = Scalar(0)
        for i in v_in:
            balance += i
        for i in v_out:
            balance -= i
        balance -= f
        if not balance == Scalar(0):
            raise ArithmeticError('Spend transaction does not balance!')
        
        # Generate spend proofs
        spend_gammas = []
        spend_states = []
        self.Q = [] # input coin public keys
        self.spend_proofs = []
        offsets = [] # for use in Fiat-Shamir challenge
        for i in range(len(q)):
            self.Q.append(G*q[i])
            offset = groth.comm(hash_to_scalar(self.Q[-1]),Scalar(0),Scalar(0))
            offsets.append(offset)
            M = [C-offset for C in C_list] # one is a commitment to zero

            spend_proof,spend_state = groth.prove_initial(M,l[i],v_in[i],r_in[i],n,m)
            self.spend_proofs.append(spend_proof)
            spend_states.append(spend_state)

        # Compute aggregate Fiat-Shamir challenge
        x = groth.challenge(C_list+offsets,self.spend_proofs)

        # Complete spend proofs
        self.spend_sigs = []
        for i in range(len(q)):
            spend_states[i].x = x
            self.spend_proofs[i],spend_gamma = groth.prove_final(self.spend_proofs[i],spend_states[i])
            spend_gammas.append(spend_gamma)

            # Spend proof signature
            self.spend_sigs.append(signature.sign(repr(self.spend_proofs[i]),q[i]))

        # Store input anonymity set and fee
        self.C_list = C_list
        self.f = f
        self.n = n
        self.m = m

        # Generate outputs
        self.C = [] # output coin commitments
        self.enc_r = [] # encrypted coin blinders
        self.enc_v = [] # encrypted coin values
        self.enc_y = [] # encrypted partial Diffie-Hellman secrets
        range_proof_data = [] # for aggregate range proof
        for i in range(len(v_out)):
            y = random_scalar()
            s = hash_to_scalar(P[i]*y) # coin serial number
            r_out = random_scalar()
            self.C.append(groth.comm(s,v_out[i],r_out)) # new output coin
            range_proof_data.append([s,v_out[i],r_out])

            # Encrypt data for recipients
            self.enc_r.append(elgamal.encrypt(r_out,P[i]))
            self.enc_v.append(elgamal.encrypt(v_out[i],P[i]))
            self.enc_y.append(elgamal.encrypt(y,P[i]))

        # Aggregate range proof
        self.range_proof = pybullet.prove(range_proof_data,BITS)

        # Balance proof
        balance_x = Scalar(0)
        balance_y = Scalar(0)
        for i in range(len(v_out)):
            balance_x += range_proof_data[i][0]
            balance_y += range_proof_data[i][2]
        balance_x *= x**m
        balance_y *= x**m
        for i in range(len(v_in)):
            balance_y -= r_in[i]*x**m
            for j in range(m):
                balance_y -= spend_gammas[i][j]*x**j

        balance_proof = schnorr.prove(balance_x,balance_y,G,H2)

        self.balance_proof = balance_proof

    # Verify the spend
    def verify(self):
        # Verify the spend proof signatures
        for i in range(len(self.spend_sigs)):
            signature.verify(repr(self.spend_proofs[i]),self.Q[i],self.spend_sigs[i])

        # Verify the spend proofs
        offsets = [] # for use in Fiat-Shamir challenge
        for i in range(len(self.spend_proofs)):
            s = hash_to_scalar(self.Q[i])
            offsets.append(groth.comm(s,Scalar(0),Scalar(0)))
        x = groth.challenge(self.C_list+offsets,self.spend_proofs)
        for i in range(len(self.spend_proofs)):
            M = [C-offsets[i] for C in self.C_list]
            groth.verify(M,self.spend_proofs[i],n,m,x)

        # Verify the aggregate range proof
        pybullet.verify([self.range_proof],BITS)

        # Verify the balance proof
        A = H1*self.f
        for i in range(len(self.C)):
            A += self.C[i]
        A *= x**self.m
        
        temp_V = Scalar(0)
        temp_R = Scalar(0)
        temp_Q = Z
        for i in range(len(self.Q)):
            temp_V += self.spend_proofs[i].zV
            temp_R += self.spend_proofs[i].zR
            for j in range(m):
                temp_Q += self.spend_proofs[i].Q[j]*x**j
        B = groth.comm(Scalar(0),temp_V,temp_R) + temp_Q

        if not self.balance_proof.Y == A-B or not self.balance_proof.W == G or not self.balance_proof.X == H2:
            raise ArithmeticError('Bad balance proof!')
        schnorr.verify(self.balance_proof)

# Alice's keys
a = random_scalar()
A = G*a

# Bob's keys
b = random_scalar()
B = G*b

# Generate a coin (and decoys) for migration
N = 11
P_old = [random_point()]*N
C_old = [random_point()]*N

p = random_scalar() # private key
r = random_scalar() # commitment mask
v = Scalar(4) # coin value
f = Scalar(1) # fee
l = random.randrange(N)
P_old[l] = H2*p
C_old[l] = com(v,r)

# Generate migration transaction to Alice and verify
print 'Migrating coin to Alice...'
migration = MigrationTransaction(P_old,C_old,l,p,v,r,f,A)
print 'Verifying...'
migration.verify()

# Mint a new coin to Alice and publicly verify
print 'Minting a new coin to Alice...'
mint = MintTransaction(Scalar(1),A)
print 'Verifying...'
mint.verify()

# Generate other fake coins for testing
n = 2
m = 3
Coins = [random_point()]*(n**m)
l = [0,0]
while l[0] == l[1]:
    l = [random.randrange(len(Coins)),random.randrange(len(Coins))] # index of the real coins
Coins[l[0]] = migration.D # the real migrated coin
Coins[l[1]] = mint.C # the real mint coin

# Alice recovers the coin blinder and private key from the migration and mint
r = [elgamal.decrypt(migration.enc_r,a),elgamal.decrypt(mint.enc_r,a)]
y = [elgamal.decrypt(migration.enc_y,a),elgamal.decrypt(mint.enc_y,a)]
v = [elgamal.decrypt(migration.enc_v,a),mint.v]

# Alice spends her coins to Bob with change to herself
print 'Spending coins to Bob with change...'
spend = SpendTransaction(Coins,n,m,[a*y[i] for i in range(2)],l,v,r,[Scalar(2),Scalar(1)],Scalar(1),[B,A])
print 'Verifying...'
spend.verify()

# Bob recovers the coin value, blinder, and private key to churn
print 'Churning coin to Bob...'
l = random.randrange(len(Coins)) # index for Bob's coin
Coins[l] = spend.C[0]
v = elgamal.decrypt(spend.enc_v[0],b)
r = elgamal.decrypt(spend.enc_r[0],b)
y = elgamal.decrypt(spend.enc_y[0],b)
churn = SpendTransaction(Coins,n,m,[b*y],[l],[v],[r],[Scalar(1)],Scalar(1),[B])
print 'Verifying...'
churn.verify()

print 'Done!'
