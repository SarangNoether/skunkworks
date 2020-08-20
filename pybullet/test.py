# Test suite for pybullet

import dumb25519
from dumb25519 import Z, G, Point, Scalar, PointVector, ScalarVector, random_point, random_scalar, hash_to_scalar, hash_to_point
import pybullet
import random
import unittest

class TestBulletOps(unittest.TestCase):
    def test_scalar_to_bits(self):
        N = 8
        scalars = [Scalar(0),Scalar(1),Scalar(2),Scalar(2**(N-1)),Scalar(2**N-1)]
        for scalar in scalars:
            bits = pybullet.scalar_to_bits(scalar,N) # break into bits

            # now reassemble the original scalar
            result = Scalar(0)
            for i,bit in enumerate(bits):
                result += bit*Scalar(2**i)
            self.assertEqual(result,scalar)

            self.assertEqual(len(bits),N)

class TestBullet(unittest.TestCase):
    def test_prove_verify_m_1_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        pybullet.verify([pybullet.prove(data,N)],N)

    def test_prove_verify_m_2_n_4(self):
        M = 2
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        pybullet.verify([pybullet.prove(data,N)],N)

    def test_invalid_value(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(2**N,2**(N+1)-1)),random_scalar()]]
        with self.assertRaises(ArithmeticError):
            pybullet.verify([pybullet.prove(data,N)],N)

    def test_batch_2_m_1_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N)
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N)
        pybullet.verify([proof1,proof2],N)

    def test_batch_2_m_1_2_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N)
        M = 2
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N)
        pybullet.verify([proof1,proof2],N)

for test in [TestBulletOps,TestBullet]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
