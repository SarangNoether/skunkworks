import dumb25519
import nozk
import unittest

class TestInnerProduct(unittest.TestCase):
    def test_N_1(self):
        a = dumb25519.ScalarVector([dumb25519.random_scalar()])
        b = dumb25519.ScalarVector([dumb25519.random_scalar()])
        with self.assertRaises(ValueError):
            nozk.test(a,b,1)

    def test_valid(self):
        for N in [2,4,8]:
            a = dumb25519.ScalarVector([dumb25519.random_scalar() for _ in range(N)])
            b = dumb25519.ScalarVector([dumb25519.random_scalar() for _ in range(N)])
            nozk.test(a,b,N)

for test in [TestInnerProduct]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
