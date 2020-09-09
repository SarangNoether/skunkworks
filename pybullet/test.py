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
        seed = random_scalar()
        aux = random_scalar()
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        aux_ = pybullet.verify([pybullet.prove(data,N,seed,aux)],N)
        self.assertEqual(aux_[0],aux)

    def test_prove_verify_m_2_n_4(self):
        M = 2
        N = 4
        seed = random_scalar()
        aux = random_scalar()
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        aux_ = pybullet.verify([pybullet.prove(data,N,seed,aux)],N)
        self.assertEqual(aux_[0],aux)

    def test_invalid_value(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(2**N,2**(N+1)-1)),random_scalar()]]
        with self.assertRaises(ArithmeticError):
            pybullet.verify([pybullet.prove(data,N)],N)

    def test_batch_2_m_1_n_4(self):
        M = 1
        N = 4
        seeds = [random_scalar(),random_scalar()]
        aux = [random_scalar(),random_scalar()]
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N,seeds[0],aux[0])
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N,seeds[1],aux[1])
        aux_ = pybullet.verify([proof1,proof2],N)
        self.assertEqual(aux_[0],aux[0])
        self.assertEqual(aux_[1],aux[1])

    def test_batch_2_m_1_2_n_4(self):
        M = 1
        N = 4
        seeds = [random_scalar(),random_scalar()]
        aux = [random_scalar(),random_scalar()]
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N,seeds[0],aux[0])
        M = 2
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N,seeds[1],aux[1])
        aux_ = pybullet.verify([proof1,proof2],N)
        self.assertEqual(aux_[0],aux[0])
        self.assertEqual(aux_[1],aux[1])

for test in [TestBulletOps,TestBullet]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
