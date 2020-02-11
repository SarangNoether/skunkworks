# Protocol test

from player import *
from dumb25519 import *

# Create shares and players
print 'Distributing shares...'
shares = []
players = []
for i in range(PLAYERS):
    shares.append(random_scalar())
    players.append(Player(shares[i],i))

# Fetch commitments
print 'Fetching commitments...'
for i in range(PLAYERS):
    for j in range(PLAYERS):
        if i == j:
            continue
        players[i].fetch_commitment(players[j])

# Fetch conversions
print 'Fetching conversions...'
for i in range(PLAYERS):
    for j in range(PLAYERS):
        if i == j:
            continue
        players[i].fetch_conversion(players[j])

# Fetch local deltas
print 'Fetching local deltas...'
for i in range(PLAYERS):
    for j in range(PLAYERS):
        if i == j:
            continue
        players[i].fetch_local_delta(players[j])

# Fetch decommits
print 'Fetching decommits...'
for i in range(PLAYERS):
    for j in range(PLAYERS):
        if i == j:
            continue
        players[i].fetch_decommit(players[j])

# Check result
print 'Checking final inversion result...'
total_shares = Scalar(0)
for i in range(PLAYERS):
    total_shares += shares[i]
expected = total_shares.invert()*U

for i in range(PLAYERS):
    if not players[i].get_result() == expected:
        raise ArithmeticError('Bad result!')
