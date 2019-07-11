# Basic transaction flow

from common import *
from dumb25519 import *
import elgamal
import signature

class Coin:
    # Mint a coin
    # INPUTS
    #   v: coin value
    #   X1,X2: destination address
    #   r: transaction private key
    #   i: index
    def __init__(self,v,X1,X2,r,i):
        # Ensure the value is in range
        if v > Scalar(2)**BITS - 1:
            raise ValueError('Value is out of range!')

        # Deterministic commitment mask
        mask = hash_to_scalar('mask',hash_to_scalar(r*X2,i))

        self.P = X1 + hash_to_scalar(r*X2,i)*G # coin public key
        self.R = r*G # recovery public key
        self.C = com(v,mask) # coin commitment
        self.enc_v = elgamal.encrypt(v,self.P) # encrypted coin value
        self.i = i # index

    # Recover a coin
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

        return p,v

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
    #  v: coin value
    #  X1,X2: destination address
    def __init__(self,v,X1,X2):
        r = random_scalar() # recovery private key

        self.coin = Coin(v,X1,X2,r,1) # minted coin
        self.v = v # plaintext coin value

        # Prove the committed value is valid
        mask = hash_to_scalar('mask',hash_to_scalar(r*X2,1))
        self.proof = signature.sign(hash_to_scalar(self.coin),mask,G)

    # Verify the mint operation
    def verify(self):
        signature.verify(hash_to_scalar(self.coin),self.coin.C-self.v*H,self.proof,G)

    # Recover the minted coin
    #
    # INPUTS
    #   x1,x2: private address
    # OUTPUTS
    #   p: coin private key
    def recover(self,x1,x2):
        p,v = self.coin.recover(x1,x2)
        return p

# Private addresses
print 'Generating addresses...'
alice = [random_scalar(),random_scalar()]
bob = [random_scalar(),random_scalar()]

# Mint a coin with value too high
try:
    print 'Minting coin with invalid value...'
    mint = MintTransaction(Scalar(2)**BITS,alice[0]*G,alice[1]*G)
except ValueError:
    pass
else:
    raise ValueError('Out-of-range mint should not succeed!')

# Mint a coin to Alice and recover
print 'Minting coin to Alice...'
mint = MintTransaction(Scalar(1),alice[0]*G,alice[1]*G)
print 'Verifying...'
mint.verify()
print 'Recovering...'
mint.recover(alice[0],alice[1])

# Bob cannot recover the minted coin
try:
    print 'Attempting invalid recovery...'
    mint.recover(bob[0],bob[1])
except ValueError:
    pass
else:
    raise ValueError('Bob should not recover a mint to Alice!')
