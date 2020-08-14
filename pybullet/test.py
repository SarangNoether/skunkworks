import dumb25519
import pybullet
import unittest

class TestInnerProduct(unittest.TestCase):
    def test_valid(self):
        print ''
        for N in [2**i for i in range(4)]:
            print 'Testing N =',N
            pybullet.test(N)

for test in [TestInnerProduct]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
