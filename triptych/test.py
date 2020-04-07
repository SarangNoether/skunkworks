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

            # Data to hide
            seed = random_scalar()
            aux1 = random_scalar()
            aux2 = random_scalar()

            # Set keys and commitments
            M = [random_point() for _ in range(2**m)] # possible signing keys
            P = [random_point() for _ in range(2**m)] # corresponding commitments
            M[l] = r*G
            P[l] = s*G

            # Run test
            proof = triptych.prove(M,P,l,r,s,m,seed,aux1,aux2)
            aux1_,aux2_ = triptych.verify(M,P,proof,m)
            self.assertEqual(aux1,aux1_)
            self.assertEqual(aux2,aux2_)

unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(TestValidProofs))
