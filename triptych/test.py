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

        for m in [2,3]: # ring size 4,8
            for w in [1,2]: # number of proofs in batch
                print 'Test parameter (m,w):',m,w
                l = random.sample(range(2**m),w) # spend indices
                r = [random_scalar() for _ in range(w)] # signing key
                s = [random_scalar() for _ in range(w)] # commitment key

                # Data to hide
                seed = [random_scalar() for _ in range(w)]
                aux1 = [random_scalar() for _ in range(w)]
                aux2 = [random_scalar() for _ in range(w)]

                # Set keys and run proofs
                M = [random_point() for _ in range(2**m)] # possible signing keys
                P = [random_point() for _ in range(2**m)] # corresponding commitments
                proofs = []
                for u in range(w):
                    M[l[u]] = r[u]*G
                    P[l[u]] = s[u]*G
                for u in range(w):
                    proofs.append(triptych.prove(M,P,l[u],r[u],s[u],m,seed[u],aux1[u],aux2[u]))

                # Verify all proofs in batch
                aux = triptych.verify(M,P,proofs,m)
                for u in range(w):
                    self.assertEqual(aux1[u],aux[u][0])
                    self.assertEqual(aux2[u],aux[u][1])

unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(TestValidProofs))
