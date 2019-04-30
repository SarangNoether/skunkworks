import dumb25519
import pybullet
import unittest

class TestInnerProduct(unittest.TestCase):
    def test_valid(self):
        for N in range(1,8):
            a = dumb25519.ScalarVector([dumb25519.random_scalar()]*N)
            b = dumb25519.ScalarVector([dumb25519.random_scalar()]*N)
            pybullet.test(a,b,N)

for test in [TestInnerProduct]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
