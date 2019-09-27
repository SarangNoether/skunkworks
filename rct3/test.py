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
    # Spend coins
    #
    # INPUTS
    #   coins: list of coins (spends and decoys)
    #   l: spend indices (corresponding coins must be recovered)
    #   dest: list of destination addresses (each a list)
    #   v: list of output coin values
    #   f: fee
    # DATA
    #   coins_in: input coins
    #   coins_out: output coins
    #   range_proof: aggregate range proof
    #   spend_proof: aggregate spend proof
    #   f: fee
    def __init__(self,coins_in,l,dest,v,f):
        # Sanity checks
        for i in l:
            if not i < len(coins_in) or not i >= 0:
                raise IndexError('Spent coin index out of bounds!')
            if coins_in[i].p is None:
                raise ValueError('Spent coin is not recovered!')
        if len(dest) == 0:
            raise ValueError('No output coins specified!')
        if not len(dest) == len(v):
            raise TypeError('Destination/value mismatch!')
        
        # Generate output coins
        coins_out = []
        r = [] # output coin masks
        for i in range(len(dest)):
            r.append(random_scalar())
            coins_out.append(Coin(v[i],dest[i][0],dest[i][1],r[i],i))

        # Generate range proof
        range_proof = pybullet.prove([[v[i],coins_out[i].mask] for i in range(len(dest))],BITS)

        # Generate balance proof secret, accounting for fee
        d = Scalar(0)
        for i in range(len(l)):
            d += coins_in[l[i]].mask
        for i in range(len(coins_out)):
            d -= coins_out[i].mask

        # Generate spend proof
        spend_proof = spend.prove([coin.P for coin in coins_in],[coin.C for coin in coins_in],l,[coins_in[l[i]].v for i in range(len(l))],[coins_in[l[i]].mask for i in range(len(l))],[coins_in[l[i]].p for i in range(len(l))],d)

        self.coins_in = coins_in
        self.coins_out = coins_out
        self.range_proof = range_proof
        self.spend_proof = spend_proof
        self.f = f

    # Verify the spend operation
    def verify(self):
        # Verify spend proof
        spend.verify(self.spend_proof,[coin.P for coin in self.coins_in],[coin.C for coin in self.coins_in],[coin.C for coin in self.coins_out]+[com(self.f,Scalar(0))])

        # Verify range proof
        pybullet.verify([self.range_proof],BITS)

# We need the ring to be large enough for this example
if not RING > 2:
    raise ValueError('Ring size is too small!')

# Private addresses
print 'Generating addresses...'
alice = [random_scalar(),random_scalar()]
bob = [random_scalar(),random_scalar()]

# Mint a coin with value too high
print 'Attempting mint with invalid value...'
try:
    mint = MintTransaction(Scalar(2)**BITS,alice[0]*G,alice[1]*G)
except ValueError:
    pass
else:
    raise ValueError('Out-of-range mint should not succeed!')

# Mint coins to Alice and recover
print 'Minting coins to Alice...'
tx_mint_1 = MintTransaction(Scalar(1),alice[0]*G,alice[1]*G)
tx_mint_2 = MintTransaction(Scalar(2),alice[0]*G,alice[1]*G)
print 'Verifying...'
tx_mint_1.verify()
tx_mint_2.verify()
print 'Recovering...'
tx_mint_1.recover(alice[0],alice[1])
tx_mint_2.recover(alice[0],alice[1])
if not com(tx_mint_1.coin.v,tx_mint_1.coin.mask) == tx_mint_1.coin.C:
    raise ValueError('Bad mint recovery!')
if not com(tx_mint_2.coin.v,tx_mint_2.coin.mask) == tx_mint_2.coin.C:
    raise ValueError('Bad mint recovery!')

# Bob cannot recover a minted coin
print 'Attempting invalid recovery...'
try:
    tx_mint_1.recover(bob[0],bob[1])
except ValueError:
    pass
else:
    raise ValueError('Bob should not recover a mint to Alice!')

# Generate ring with decoys
print 'Building ring...'
ring = []
for i in range(RING):
    ring.append(Coin(Scalar(10),random_point(),random_point(),random_scalar(),random_scalar()))
ring[0] = tx_mint_1.coin
ring[1] = tx_mint_2.coin

# Alice spends the coins to Bob
print 'Spending coins from Alice to Bob...'
tx_spend = SpendTransaction(ring,[0,1],[[bob[0]*G,bob[1]*G]],[Scalar(2)],Scalar(1))
print 'Verifying...'
tx_spend.verify()

# Bad balance
print 'Attempting spend with bad balance...'
try:
    tx_spend = SpendTransaction(ring,[0,1],[[bob[0]*G,bob[1]*G]],[Scalar(2)],Scalar(0))
    tx_spend.verify()
except ArithmeticError:
    pass
else:
    raise ArithmeticError('Spend with bad balance should not verify!')
