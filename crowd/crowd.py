# Simple test of "How to Squeeze a Crowd" uniform selection
# https://isi.jhu.edu/~mgreen/mixing.pdf
#
# Uses a keyed hash to make a uniform ring selection with one true input

from dumb25519 import *
from random import randint
from scipy.stats import chisquare,variation

N = 11 # ring size
L = 100 # ledger size
TRIALS = 100000 # tests to run

# Produce the output of a keyed hash function
# IN: key k (arbitrary), index i (arbitrary)
# OUT: hash output in Z_l
def f(k,i):
    return int(hash_to_scalar(k,i))

# Generate a uniform sampling in the ledger
# IN: index I (int)
# OUT: ledger indices (int list)
def sample(I):
    k = random_scalar() # hash key
    j = randint(0,N-1) # true index in ring

    y = (f(k,j) - I) % L
    T = [] # ring indices
    for i in range(N):
        T.append((f(k,i)-y)%L)
    return T

# Run basic trials
print 'Running',TRIALS,'trials with ring size',N,'and ledger size',L
hits = [0]*L
for i in range(TRIALS):
    j = randint(0,L-1)
    T = sample(j)
    T.index(j) # ensure the true input is in the ring

    # Log the results
    for k in T:
        hits[int(k)] += 1

# Check coefficient of variation
print 'Coefficient of variation:',variation(hits)

# Run a chi-squared test
print 'Chi-squared p:',chisquare(hits).pvalue
