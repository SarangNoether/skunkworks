# MPC player

from dumb25519 import *
from paillier import *
from schnorr import *

# Player states
PLAYER_STATE_AWAITING_COMMITMENTS = 0
PLAYER_STATE_AWAITING_SHARES = 1
PLAYER_STATE_AWAITING_DELTAS = 2
PLAYER_STATE_AWAITING_DECOMMITS = 3
PLAYER_STATE_COMPLETE = 4

PLAYERS = 3
U = hash_to_point('U')

# Test for list completion (except for index `i`)
def complete(data,i):
    for j in range(len(data)):
        if j != i and data[j] is None:
            return False
    return True

class Player:
    # Initialize a player with a given share
    #
    # INPUT
    #   ident: identifier index (int)
    #   x: secret share (Scalar)
    def __init__(self,x,ident):
        if not isinstance(ident,int) or ident < 0 or ident >= PLAYERS:
            raise IndexError('Bad player ident!')
        self.ident = ident

        # Set secret share
        if not isinstance(x,Scalar):
            raise TypeError('Bad share!')
        self.x = x

        # Set up encryption keys
        self.private_key = PaillierPrivateKey()
        self.public_key = self.private_key.get_public()

        # Generate commitment
        self.gamma = random_scalar()
        self.commit_mask = random_scalar()
        self.commit = hash_to_point('MPC gamma commit',self.gamma*U,self.commit_mask)

        # Generate Schnorr proof
        self.proof = SchnorrProof(self.gamma,self.gamma*U,U)

        # Other player data
        self.alpha = [None for _ in range(PLAYERS)]
        self.beta = [None for _ in range(PLAYERS)]
        self.commits = [None for _ in range(PLAYERS)]
        self.local_deltas = [None for _ in range(PLAYERS)]
        self.proofs = [None for _ in range(PLAYERS)]
        self.gamma_U = [None for _ in range(PLAYERS)]

        self.state = PLAYER_STATE_AWAITING_COMMITMENTS

    # Get ident
    #
    # RETURNS
    #   ident (int)
    def get_ident(self):
        return self.ident
    
    # Get public encryption key
    #
    # RETURNS
    #   public key (PaillierPublicKey)
    def get_public_key(self):
        return self.public_key

    # Get commitment
    #
    # RETURNS
    #   commitment (Scalar)
    def get_commit(self):
        return self.commit

    # Get local delta
    #
    # RETURNS
    #   local delta (Scalar)
    def get_local_delta(self):
        if self.state < PLAYER_STATE_AWAITING_DELTAS:
            raise Exception('Bad state!')
        return self.local_delta

    # Get decommitment data
    #
    # RETURNS
    #   Schnorr proof (SchnorrProof)
    #   gamma*U (Point)
    #   commmitment mask (Scalar)
    def get_decommit(self):
        if self.state < PLAYER_STATE_AWAITING_DECOMMITS:
            raise Exception('Bad state!')
        return self.proof,self.gamma*U,self.commit_mask

    # Get the final inversion
    #
    # RETURNS
    #   inversion result (Point)
    def get_result(self):
        if self.state != PLAYER_STATE_COMPLETE:
            raise Exception('Bad state!')
        return self.R

    # Fetch a commitment
    #
    # INPUT
    #   friend: other player (Player)
    def fetch_commitment(self,friend):
        if not isinstance(friend,Player):
            raise TypeError('Bad friend!')

        self.commits[friend.get_ident()] = friend.get_commit()
        if complete(self.commits,self.get_ident()):
            self.state = PLAYER_STATE_AWAITING_SHARES

    # Fetch a share conversion
    #
    # INPUT
    #   friend: other player for exchange (Player)
    def fetch_conversion(self,friend):
        if not isinstance(friend,Player):
            raise TypeError('Bad friend!')

        c = friend.get_conversion_reply(self.public_key.encrypt(self.x),self)
        if not isinstance(c,long):
            raise TypeError('Bad share conversion reply!')

        self.alpha[friend.get_ident()] = self.private_key.decrypt(c)

        self.check_deltas()
        friend.check_deltas()

    # Check for all share conversions
    def check_deltas(self):
        if complete(self.alpha,self.get_ident()) and complete(self.beta,self.get_ident()):
            # Compute local delta
            self.local_delta = self.x*self.gamma
            for i in range(PLAYERS):
                if i == self.get_ident():
                    continue
                self.local_delta += self.alpha[i] + self.beta[i]

            self.state = PLAYER_STATE_AWAITING_DELTAS

    # Get a share conversion reply
    #
    # INPUT
    #   c: conversion message (long)
    #   friend: other player for exchange (Player)
    # RETURNS
    #   share conversion reply (long)
    def get_conversion_reply(self,c,friend):
        if not isinstance(c,long):
            raise TypeError('Bad share conversion message!')
        if not isinstance(friend,Player):
            raise TypeError('Bad friend!')
        if not self.state == PLAYER_STATE_AWAITING_SHARES:
            raise Exception('Incorrect state!')

        self.beta[friend.get_ident()] = random_scalar()
        d = pow(c,self.gamma.x,friend.get_public_key().N**2)
        d = (d*friend.get_public_key().encrypt(-self.beta[friend.get_ident()])) % friend.get_public_key().N**2

        return d

    # Fetch a local delta
    #
    # INPUT
    #   friend: other player (Player)
    def fetch_local_delta(self,friend):
        if not isinstance(friend,Player):
            raise TypeError('Bad friend!')

        self.local_deltas[friend.get_ident()] = friend.get_local_delta()
        if complete(self.local_deltas,self.get_ident()):
            self.state = PLAYER_STATE_AWAITING_DECOMMITS

    # Fetch decommitment data
    #
    # INPUT
    #   friend: other player (Player)
    def fetch_decommit(self,friend):
        if not isinstance(friend,Player):
            raise TypeError('Bad friend!')

        (proof,gamma_U,mask) = friend.get_decommit()
        self.proofs[friend.get_ident()] = proof
        self.gamma_U[friend.get_ident()] = gamma_U

        if not self.commits[friend.get_ident()] == hash_to_point('MPC gamma commit',gamma_U,mask):
            raise ValueError('Bad decommitment!')
        if not proof.verify(gamma_U,U):
            raise ArithmeticError('Bad Schnorr verification!')

        if complete(self.proofs,self.get_ident()) and complete(self.gamma_U,self.get_ident()):
            # Construct the final inversion
            inv = self.local_delta
            for i in range(PLAYERS):
                if i == self.get_ident():
                    continue
                inv += self.local_deltas[i]
            inv = inv.invert()

            self.R = self.gamma*U
            for i in range(PLAYERS):
                if i == self.get_ident():
                    continue
                self.R += self.gamma_U[i]
            self.R *= inv

            self.state = PLAYER_STATE_COMPLETE
