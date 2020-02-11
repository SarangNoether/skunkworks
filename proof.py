# Proofs of spend/non-spend status

from dumb25519 import *
import transcript

# Constants
STATUS_SPEND = 0
STATUS_NON_SPEND = 1

# Data for a coin
class Coin:
    # Mint a coin
    #
    # INPUT
    #   address: recipient address (Address)
    # RAISES
    #   TypeError on bad input type
    def __init__(self,address):
        if not isinstance(address,Address):
            raise TypeError('Bad input type!')

        r = random_scalar()
        self.R = r*G # transaction public key
        self.P = hash_to_scalar(r*address.A)*G + address.B # coin public key
        self.p = None # coin private key
        self.I = None # key image

    # Recover a coin's private data
    #
    # INPUT
    #   key: control address (Address)
    # RETURNS
    #   True on successful recovery
    # RAISES
    #   TypeError on bad input type
    #   ArithmeticError on failed recovery
    def recover(self,key):
        if not isinstance(key,Address):
            raise TypeError('Bad input type!')

        if not hash_to_scalar(key.a*self.R)*G + key.b*G == self.P:
            raise ArithmeticError('Unable to recover coin!')

        self.p = hash_to_scalar(key.a*self.R) + key.b
        self.I = self.p*hash_to_point(self.P)

        return True

# Data for an address
class Address:
    def __init__(self):
        self.a = random_scalar() # private view key
        self.b = random_scalar() # private spend key
        self.A = self.a*G # public view key
        self.B = self.b*G # public spend key

# Multiple-base Schnorr equality proof
class SchnorrProof:
    # Generate a proof
    #
    # INPUT
    #   w: common discrete logarithm (Scalar)
    #   P,Q: points such that each `P[i] == w*Q[i]` (Point lists)
    #   message: optional message (hashable)
    # RAISES
    #   TypeError on bad input types
    #   IndexError on input list mismatch
    #   ValueError on bad input validity
    def __init__(self,w,P,Q,message=None):
        if not isinstance(w,Scalar) or not isinstance(P,PointVector) or not isinstance(Q,PointVector):
            raise TypeError('Bad input type!')
        if not len(P) == len(Q) or len(P) == 0:
            raise IndexError('Bad input size!')

        # Check point validity
        for i in range(len(P)):
            if not P[i] == w*Q[i]:
                raise ValueError('Bad input validity!')

        tr = transcript.Transcript('Multi-Schnorr proof')
        if message is not None:
            tr.update(message)

        k = random_scalar()
        tr.update(P)
        tr.update(Q)
        for i in range(len(Q)):
            tr.update(k*Q[i])
        self.c = tr.challenge()
        self.s = k - self.c*w

    # Verify a proof
    #
    # INPUT
    #   w: common discrete logarithm (Scalar)
    #   P,Q: points such that each `P[i] == w*Q[i]` (Point lists)
    #   message: optional message (hashable)
    # RETURNS
    #   True on successful verification
    # RAISES
    #   TypeError on bad input types
    #   IndexError on input list mismatch
    #   ArithmeticError on failed verification
    def verify(self,P,Q,message=None):
        if not isinstance(P,PointVector) or not isinstance(Q,PointVector):
            raise TypeError('Bad input type!')
        if not len(P) == len(Q) or len(P) == 0:
            raise IndexError('Bad input size!')

        tr = transcript.Transcript('Multi-Schnorr proof')
        if message is not None:
            tr.update(message)
        tr.update(P)
        tr.update(Q)
        for i in range(len(Q)):
            tr.update(self.s*Q[i] + self.c*P[i])
        if not tr.challenge() == self.c:
            raise ArithmeticError('Failed verification!')

        return True

# Proof of coin spend status
class SpendProof:
    # Generate a proof
    #
    # INPUT
    #   coin: coin (Coin)
    #   address: control address (Address)
    #   status: STATUS_SPEND or STATUS_NON_SPEND (int)
    #   I: key image if STATUS_NON_SPEND (Point, optional)
    # RAISES
    #   TypeError on bad input type
    def __init__(self,coin,address,status,I=None):
        if not isinstance(coin,Coin) or not isinstance(address,Address) or not status in [STATUS_SPEND,STATUS_NON_SPEND]:
            raise TypeError('Bad input type!')
        if I is not None and not isinstance(I,Point):
            raise TypeError('Bad input type!')

        # Recover the coin
        coin.recover(address)

        # Spend proofs
        self.points = PointVector([])
        if status == STATUS_SPEND:
            self.points.append(address.b*(coin.I - hash_to_scalar(address.a*coin.R)*hash_to_point(coin.P)))
            self.points.append(address.b*address.B)
            w = address.b
            P = PointVector([address.B,self.points[0],self.points[1]])
            Q = PointVector([G,coin.I - hash_to_scalar(address.a*coin.R)*hash_to_point(coin.P),address.B])
            self.proof1 = SchnorrProof(w,P,Q)
        else:
            self.points.append(address.b*(I - hash_to_scalar(address.a*coin.R)*hash_to_point(coin.P)))
            self.points.append(address.b*address.B)
            w = address.b
            P = PointVector([address.B,self.points[0],self.points[1]])
            Q = PointVector([G,I - hash_to_scalar(address.a*coin.R)*hash_to_point(coin.P),address.B])
            self.proof1 = SchnorrProof(w,P,Q)

        self.points.append(address.b**2*G)
        self.points.append(address.b**2*hash_to_point(coin.P))
        w = address.b**2
        P = PointVector([self.points[2],self.points[3]])
        Q = PointVector([G,hash_to_point(coin.P)])
        self.proof2 = SchnorrProof(w,P,Q)

    # Verify a proof
    #
    # INPUT
    #   coin: coin (Coin)
    #   address: control address (Address)
    #   status: STATUS_SPEND or STATUS_NON_SPEND (int)
    #   I: key image (Point)
    # RETURNS
    #   True on successful verification
    # RAISES
    #   TypeError on bad input type
    #   ArithmeticError on failed verification
    def verify(self,coin,address,status,I):
        if not isinstance(coin,Coin) or not isinstance(address,Address) or not status in [STATUS_SPEND,STATUS_NON_SPEND] or not isinstance(I,Point):
            raise TypeError('Bad input type!')

        # Verify Schnorr proofs
        P = PointVector([address.B,self.points[0],self.points[1]])
        Q = PointVector([G,I - hash_to_scalar(address.a*coin.R)*hash_to_point(coin.P),address.B])
        self.proof1.verify(P,Q)

        P = PointVector([self.points[2],self.points[3]])
        Q = PointVector([G,hash_to_point(coin.P)])
        self.proof2.verify(P,Q)

        # Check point equality
        if not self.points[1] == self.points[2]:
            raise ArithmeticError('Failed verification!')
        if status == STATUS_SPEND and self.points[0] != self.points[3]:
            raise ArithmeticError('Failed verification!')
        if status == STATUS_NON_SPEND and self.points[0] == self.points[3]:
            raise ArithmeticError('Failed verification!')

        return True
