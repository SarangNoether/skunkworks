# Basic transaction flow

from common import *
from dumb25519 import *
import elgamal
import signature
import pybullet
import spend

class Coin:
    # Generate a new coin
    # INPUTS
    #   v: coin value
    #   X1,X2: destination address
    #   r: transaction private key
    #   i: index
    # DATA
    #   P: coin public key
    #   R: recovery public key
    #   C: value commitment
    #   enc_v: encrypted value
    #   i: index in transaction
    #   p: coin private key (after recovery)
    #   v: coin value (after recovery)
    def __init__(self,v,X1,X2,r,i):
        # Sanity checks
        if not isinstance(v,Scalar):
            raise TypeError('Invalid coin value!')
        if v > Scalar(2)**BITS - 1:
            raise ValueError('Value is out of range!')
        if not isinstance(X1,Point) or not isinstance(X2,Point):
            raise TypeError('Invalid destination address!')
        if not isinstance(r,Scalar):
            raise TypeError('Invalid recovery private key!')

        # Deterministic commitment mask
        mask = hash_to_scalar('mask',hash_to_scalar(r*X2,i))

        # Coin data
        self.P = X1 + hash_to_scalar(r*X2,i)*G
        self.R = r*G
        self.C = com(v,mask)
        self.enc_v = elgamal.encrypt(v,self.P)
        self.i = i
        self.p = None
        self.v = None
        self.mask = mask # private data

    # Recover a coin's private data
    # INPUTS
    #   x1,x2: private address
    # OUTPUTS
    #   p: coin private key
    #   v: coin value
    def recover(self,x1,x2):
        # Attempt to recover the coin private key
        p = x1 + hash_to_scalar(x2*self.R,self.i)
        if not p*G == self.P:
            raise ValueError('Failed to recover coin!')

        # Recover the coin value
        v = elgamal.decrypt(self.enc_v,p)

        # Confirm the commitment is valid
        if not com(v,hash_to_scalar('mask',hash_to_scalar(x2*self.R,self.i))) == self.C:
            raise ValueError('Coin commitment does not match!')

        self.p = p
        self.v = v

    def __repr__(self):
        r = '<Coin> '
        r += 'P:' + repr(self.P) + '|'
        r += 'R:' + repr(self.R) + '|'
        r += 'C:' + repr(self.C) + '|'
        r += 'enc_v:' + repr(self.enc_v) + '|'
        r += 'i:' + repr(self.i)
        return r


# The result of a mint operation
class MintTransaction:
    # Mint a coin
    #
    # INPUTS
    #   v: coin value
    #   X1,X2: destination address
    # DATA
    #   coin: minted coin
    #   v: value
    #   proof: Schnorr signature of correct commitment value
    def __init__(self,v,X1,X2):
        # Sanity checks
        if not isinstance(v,Scalar):
            raise TypeError('Invalid coin value!')
        if not isinstance(X1,Point) or not isinstance(X2,Point):
            raise TypeError('Invalid destination address!')

        r = random_scalar() # recovery private key

        # Minted coin data
        self.coin = Coin(v,X1,X2,r,1)
        self.v = v

        # Prove the committed value is valid
        mask = hash_to_scalar('mask',hash_to_scalar(r*X2,1))
        self.proof = signature.sign(hash_to_scalar(self.coin),mask,Gc)

    # Verify the mint operation
    def verify(self):
        signature.verify(hash_to_scalar(self.coin),self.coin.C-self.v*Hc,self.proof,Gc)

    # Recover the minted coin
    #
    # INPUTS
    #   x1,x2: private address
    def recover(self,x1,x2):
        self.coin.recover(x1,x2)

# The result of a spend transaction
class SpendTransaction:
    # Spend a coin
    #
    # INPUTS
    #   coins: list of coins (spend and decoys)
    #   l: spend index (corresponding coin must be recovered)
    #   dest: list of destination addresses (each a list)
    #   v: list of output coin values
    # DATA
    #   coins_in: input coins
    #   coins_out: output coins
    #   C1: commitment offset
    #   range: aggregate range proof
    #   spend_proof: spend proof
    #   bal_c: balance proof c
    #   bal_z: balance proof z
    def __init__(self,coins,l,dest,v):
        # Sanity checks
        if not l < len(coins) or not l >= 0:
            raise IndexError('Spent coin index out of bounds!')
        if coins[l].p is None:
            raise ValueError('Spent coin is not recovered!')
        if len(dest) == 0:
            raise ValueError('No output coins specified!')
        if not len(dest) == len(v):
            raise TypeError('Destination/value mismatch!')
        
        self.coins_in = coins

        # Generate output coins
        self.coins_out = []
        r = [] # output coin masks
        for i in range(len(dest)):
            r.append(random_scalar())
            self.coins_out.append(Coin(v[i],dest[i][0],dest[i][1],r[i],i))

        # Generate range proof
        self.range = pybullet.prove([[v[i],self.coins_out[i].mask] for i in range(len(dest))],BITS)

        # Offset input coin
        delta = random_scalar()
        self.C1 = coins[l].C - delta*Gc

        # Generate balance proof
        d = Scalar(0)
        for i in range(len(self.coins_out)):
            d += self.coins_out[i].mask
        d -= (coins[l].mask - delta)
        r1 = random_scalar()
        self.bal_c = hash_to_scalar(r1*Gc,self.coins_out,coins)
        self.bal_z = r1 + d*self.bal_c

        # Generate spend proof
        self.spend_proof = spend.prove([coin.P for coin in coins],[coin.C for coin in coins],l,coins[l].v,coins[l].mask,delta,coins[l].p)

    # Verify the spend operation
    def verify(self):
        spend.verify(self.spend_proof,[coin.P for coin in self.coins_in],[coin.C for coin in self.coins_in],self.C1)

# Private addresses
print 'Generating addresses...'
alice = [random_scalar(),random_scalar()]
bob = [random_scalar(),random_scalar()]

# Mint a coin with value too high
MINT = Scalar(1) # value
try:
    print 'Attempting mint with invalid value...'
    mint = MintTransaction(Scalar(2)**BITS,alice[0]*G,alice[1]*G)
except ValueError:
    pass
else:
    raise ValueError('Out-of-range mint should not succeed!')

# Mint a coin to Alice and recover
print 'Minting coin to Alice...'
mint = MintTransaction(MINT,alice[0]*G,alice[1]*G)
print 'Verifying...'
mint.verify()
print 'Recovering...'
mint.recover(alice[0],alice[1])
if not mint.coin.v == MINT:
    raise ValueError('Bad mint recovery!')

# Bob cannot recover the minted coin
try:
    print 'Attempting invalid recovery...'
    mint.recover(bob[0],bob[1])
except ValueError:
    pass
else:
    raise ValueError('Bob should not recover a mint to Alice!')

# Generate ring with decoys
print 'Building decoys...'
ring = []
for i in range(RING):
    ring.append(Coin(Scalar(10),random_point(),random_point(),random_scalar(),random_scalar()))
ring[1] = mint.coin

# Alice spends the coin to Bob
print 'Spending coin from Alice to Bob...'
spend_tx = SpendTransaction(ring,1,[[bob[0]*G,bob[1]*G]],[MINT])
print 'Verifying...'
spend_tx.verify()
