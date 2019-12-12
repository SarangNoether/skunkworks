# Inverse MPC with Paillier, assuming honest-but-curious players
#
# See https://eprint.iacr.org/2019/114 for the method.
# NOTE: This is for algorithm testing only. Do not use in production.

import random
from dumb25519 import *

MILLER_RABIN = 64 # number of Miller-Rabin tests
PRIME_BITS = 256 # bits in primes used for keys
PLAYERS = 3 # number of MPC players

print 'Testing MPC inversion with',PLAYERS,'players...'

# Use the Miller-Rabin test to determine if `n` is probably prime
def prime(n):
    if n in [0,1]:
        raise ValueError('Primality is not defined for n < 2')

    # Even?
    if n % 2 == 0:
        return False

    # Find `k`, `q` such that `n - 1 = q*2**k` with `q` odd
    q = n - 1
    k = 0
    while q % 2 == 0:
        q /= 2
        k += 1
    if not q % 2 == 1 or not n - 1 == q*2**k:
        raise ArithmeticError('Failed to decompose prime candidate')

    for _ in range(MILLER_RABIN):
        a = random.randrange(2,n - 2)
        a = pow(a,q,n)
        if a == 1 or a == n - 1:
            continue

        for _ in range(k):
            if a == n - 1:
                break
            a = a*a % n
        else:
            return False
    return True

# Compute `c` such that `a*c = 1 (mod b)`
def invert(a,b):
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 / r1
        r0, r1 = r1, r0 - q*r1
        s0, s1 = s1, s0 - q*s1
        t0, t1 = t1, t0 - q*t1
    if r0 != 1:
        raise ArithmeticError('Inverse does not exist')

    if not (s0*a) % b == 1:
        raise ArithmeticError('Error computing inverse')

    return s0 % b

# Paillier keys and cryptography, with Scalar messages
class Key:
    def generate(self):
        # Select random primes of the appropriate length
        p = None
        q = None
        while True:
            p = random.randrange(2**(PRIME_BITS - 1),2**PRIME_BITS) | 1
            if prime(p):
                break
        while True:
            q = random.randrange(2**(PRIME_BITS - 1),2**PRIME_BITS) | 1
            if prime(q):
                break

        # Key generation
        self.N = p*q
        self.phi = (p - 1)*(q - 1)
        invert(self.phi,self.N)

    # Encrypt a message `m`
    def encrypt(self,m):
        m = m.x # from Scalar type

        if m < 0 or m >= self.N:
            raise ValueError('Message is out of range')

        temp_N = pow(1 + self.N,m,self.N**2)
        temp_r = pow(random.randrange(1,self.N),self.N,self.N**2)

        return (temp_N*temp_r) % self.N**2

    # Decrypt a ciphertext `c`
    def decrypt(self,c):
        return Scalar(((pow(c,self.phi,self.N**2) - 1)//self.N * invert(self.phi,self.N)) % self.N) # to Scalar type

# Test keys and cryptography
for _ in range(0):
    key = Key()
    key.generate()
    m = random.randrange(key.N)

    # Test message decryption
    if not key.decrypt(key.encrypt(m)) == m:
        raise ArithmeticError('Test failure: message decryption')

    # Test additive homomorphicity
    n = random.randrange(key.N)
    if not key.decrypt((key.encrypt(m)*key.encrypt(n)) % key.N**2) == (m + n) % key.N:
        raise ArithmeticError('Test failure: additive homomorphicity')

    # Test scalar homomorphicity
    if not key.decrypt(pow(key.encrypt(m),n,key.N**2)) == (m*n) % key.N:
        raise ArithmeticError('Test failure: scalar homomorphicity')

# Collaboratively compute `x*U`, where each player holds an additive share of `x`
U = hash_to_point('U')

# Key shares
#
# x: secret
x = []
for _ in range(PLAYERS):
    x.append(random_scalar())

# Paillier keys
#
# paillier: static and shared
paillier = []
for _ in range(PLAYERS):
    key = Key()
    key.generate()
    paillier.append(key)

# Random selection
#
# gamma: secret
# U_gamma: to dealer
gamma = []
U_gamma = []
for _ in range(PLAYERS):
    temp = random_scalar()
    gamma.append(temp)
    U_gamma.append(temp*U)

# All players compute alpha, beta
#
# alpha: pairwise shared
# beta: pairwise shared
alpha = [[None for _ in range(PLAYERS)] for _ in range(PLAYERS)]
beta = [[None for _ in range(PLAYERS)] for _ in range(PLAYERS)]
for i in range(PLAYERS):
    for j in range(PLAYERS):
        if i == j:
            continue
        
        beta[j][i] = random_scalar()

        ci = paillier[i].encrypt(x[i])
        cj = pow(ci,gamma[j].x,paillier[i].N**2)
        cj = (cj * paillier[i].encrypt(-beta[j][i])) % (paillier[i].N**2)

        alpha[i][j] = paillier[i].decrypt(cj)

        # Test share product reconstruction
        if not alpha[i][j] + beta[j][i] == x[i]*gamma[j]:
            raise ArithmeticError('Failed to reconstruct share product!')

# Construct delta
#
# delta: to dealer
delta = []
for i in range(PLAYERS):
    temp = x[i]*gamma[i]
    for j in range(PLAYERS):
        if i == j:
            continue
        temp += alpha[i][j] + beta[j][i]

    delta.append(temp)

# Construct inverse (performed by dealer)
inv = Scalar(0)
for i in range(PLAYERS):
    inv += delta[i]
inv = inv.invert()

R = Z
for i in range(PLAYERS):
    R += U_gamma[i]
R *= inv

# Test MPC result
test_x = Scalar(0)
for i in range(PLAYERS):
    test_x += x[i]
if not R == test_x.invert()*U:
    raise('Final test failed')

print 'Success!'
