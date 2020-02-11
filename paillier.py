# Paillier homomorphic encryption

from dumb25519 import *
import random

# Constants
MILLER_RABIN = 64 # number of Miller-Rabin tests
PRIME_BITS = 256 # bits in primes used for Paillier keys

# Use the Miller-Rabin test to determine if `n` is probably prime
#
# INPUT
#   n: candidate number (long)
# RETURNS
#   True if probably prime
#   False otherwise
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

# Modular inversion
#
# INPUT
#   a: value (long)
#   b: modulus (long)
# RETURNS
#   `c` such that `a*c == 1 (mod b)`
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

class PaillierPublicKey:
    # Set up a public key
    #
    # INPUT
    #   N: modulus (long)
    def __init__(self,N):
        if not isinstance(N,long):
            raise TypeError('Bad public key!')
        self.N = N

    # Encrypt a message
    #
    # INPUT
    #   m: message (Scalar)
    # RETURNS
    #   ciphertext message (long)
    def encrypt(self,m):
        if not isinstance(m,Scalar):
            raise TypeError('Bad message!')

        # Extract integer value
        m = m.x

        if m < 0 or m >= self.N:
            raise ValueError('Message is out of range')

        temp_N = pow(1 + self.N,m,self.N**2)
        temp_r = pow(random.randrange(1,self.N),self.N,self.N**2)

        return (temp_N*temp_r) % self.N**2

class PaillierPrivateKey:
    # Set up a private key
    def __init__(self):
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

        self.N = p*q
        self.phi = (p - 1)*(q - 1)

    # Get the public key
    #
    # RETURNS
    #   public key (long)
    def get_public(self):
        return PaillierPublicKey(self.N)

    # Decrypt a message
    #
    # INPUT
    #   c: message (long)
    # RETURNS
    #   plaintext message (Scalar)
    def decrypt(self,c):
        if not isinstance(c,long):
            raise TypeError('Bad message!')

        return Scalar(((pow(c,self.phi,self.N**2) - 1)/self.N * invert(self.phi,self.N)) % self.N)
