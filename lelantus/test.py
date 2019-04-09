# Test suite for Lelantus

import dumb25519
from dumb25519 import Z, G, Point, Scalar, PointVector, ScalarVector, random_point, random_scalar, hash_to_scalar, hash_to_point
import pybullet
import schnorr
import groth
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

    def test_sum_scalar(self):
        # test correctness
        for s in [Scalar(0),Scalar(1),Scalar(2),Scalar(3)]:
            for l in [0,1,2,4,8]:
                result = Scalar(0)
                for i in range(l):
                    result += s**i
                self.assertEqual(result,pybullet.sum_scalar(s,l))

        # fail if l is not a power of 2
        with self.assertRaises(ValueError):
            pybullet.sum_scalar(Scalar(1),3)

class TestBullet(unittest.TestCase):
    def test_prove_verify_m_1_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        pybullet.verify([pybullet.prove(data,N)],N)

    def test_prove_verify_m_2_n_4(self):
        M = 2
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        pybullet.verify([pybullet.prove(data,N)],N)

    def test_invalid_value(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(2**N,2**(N+1)-1)),random_scalar(),random_scalar()]]
        with self.assertRaises(ArithmeticError):
            pybullet.verify([pybullet.prove(data,N)],N)

    def test_batch_2_m_1_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N)
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N)
        pybullet.verify([proof1,proof2],N)

    def test_batch_2_m_1_2_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N)
        M = 2
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N)
        pybullet.verify([proof1,proof2],N)

    def test_invalid_batch_2_m_1_2_n_4(self):
        M = 1
        N = 4
        data = [[Scalar(random.randint(0,2**N-1)),random_scalar(),random_scalar()] for i in range(M)]
        proof1 = pybullet.prove(data,N)
        M = 2
        data = [[Scalar(random.randint(2**N,2**(N+1)-1)),random_scalar(),random_scalar()] for i in range(M)]
        proof2 = pybullet.prove(data,N)
        with self.assertRaises(ArithmeticError):
            pybullet.verify([proof1,proof2],N)

class TestSchnorr(unittest.TestCase):
    def test_random(self):
        H = hash_to_point('schnorr H')
        schnorr.verify(schnorr.prove(random_scalar(),random_scalar(),G,H))

class TestGroth(unittest.TestCase):
    def test_1(self):
        v = random_scalar()
        r = random_scalar()
        M = [groth.comm(Scalar(0),v,r)]
        n = 1
        m = 1
        l = 0
        proof = groth.prove(M,l,v,r,n,m)
        groth.verify(M,proof,n,m)

    def test_2_0(self):
        n = 2
        m = 1
        l = 0
        N = n**m
        v = [random_scalar()]*N
        r = [random_scalar()]*N
        M = [groth.comm(random_scalar(),v[i],r[i]) for i in range(N)]
        M[l] = groth.comm(Scalar(0),v[l],r[l])
        proof = groth.prove(M,l,v[l],r[l],n,m)
        groth.verify(M,proof,n,m)

    def test_2_1(self):
        n = 2
        m = 1
        l = 1
        N = n**m
        v = [random_scalar()]*N
        r = [random_scalar()]*N
        M = [groth.comm(random_scalar(),v[i],r[i]) for i in range(N)]
        M[l] = groth.comm(Scalar(0),v[l],r[l])
        proof = groth.prove(M,l,v[l],r[l],n,m)
        groth.verify(M,proof,n,m)

for test in [TestBulletOps,TestBullet,TestSchnorr,TestGroth]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
