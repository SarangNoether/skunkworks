import arcturus
import unittest
import dumb25519
from dumb25519 import random_scalar, random_point, Scalar
import random

G = dumb25519.G
H = dumb25519.hash_to_point('H')

class TestValidProofs(unittest.TestCase):
    def test_valid_prove_verify(self):
        print ''

        for m in [1,2]: # ring size 2,4
            for spends in range(1,min(3,2**m)+1):
                for outs in [1,2,3]:
                    print 'Test parameters (m spends outs):',m,spends,outs
                    l = random.sample(range(2**m),spends) # spend indices
                    r = [random_scalar() for _ in range(spends)] # signing keys
                    s = [random_scalar() for _ in range(spends)] # input commitment blinders
                    a = [random_scalar() for _ in range(spends)] # input commitment amounts
                    t = [random_scalar() for _ in range(outs)] # output commitment blinders
                    b = [random_scalar() for _ in range(outs)] # output commitment amounts

                    # Balance amounts
                    b[0] = Scalar(0)
                    for i in range(len(a)):
                        b[0] += a[i]
                    for i in range(1,len(b)):
                        b[0] -= b[i]

                    # Data to hide
                    seed = random_scalar()
                    aux1 = random_scalar()
                    aux2 = random_scalar()

                    # Set keys and commitments
                    M = [random_point() for _ in range(2**m)] # possible signing keys
                    P = [random_point() for _ in range(2**m)] # corresponding commitments
                    Q = []
                    for i in range(outs): # output commitments
                        Q.append(t[i]*G + b[i]*H)
                    for i in range(spends): # spend commitments
                        M[l[i]] = r[i]*G
                        P[l[i]] = s[i]*G + a[i]*H

                    # Run test
                    proof = arcturus.prove(M,P,Q,l,r,s,t,a,b,m,seed,aux1,aux2)
                    aux1_,aux2_ = arcturus.verify(M,P,Q,proof,m)
                    self.assertEqual(aux1,aux1_)
                    self.assertEqual(aux2,aux2_)

unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(TestValidProofs))
