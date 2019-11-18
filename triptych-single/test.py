import triptych
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
            print 'Test parameter (m):',m
            l = random.randrange(2**m) # spend index
            r = random_scalar() # signing key
            s = random_scalar() # commitment key

            # Set keys and commitments
            M = [random_point() for _ in range(2**m)] # possible signing keys
            P = [random_point() for _ in range(2**m)] # corresponding commitments
            M[l] = r*G
            P[l] = s*G

            # Run test
            self.assertTrue(triptych.verify(M,P,triptych.prove(M,P,l,r,s,m),m))

unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(TestValidProofs))
