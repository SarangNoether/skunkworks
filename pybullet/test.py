# Test suite for pybullet

import dumb25519
from dumb25519 import Z, G, Point, Scalar, PointVector, ScalarVector, random_point, random_scalar, hash_to_scalar, hash_to_point
import pybullet
import random
import unittest

class TestBulletOps(unittest.TestCase):
    # Scalar bit decomposition
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

    # Scalar sums
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
    # Valid proof with 1 input
    def test_prove_verify_m_1_n_4(self):
        pybullet.N = 4

        proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)
        proof_C = pybullet.prove_C(state,proof.x)
        proof = pybullet.aggregate_C([proof_C],proof)

        pybullet.verify([proof])

    # Evil dealer with 1 input, challenge y=0
    def test_invalid_y0_m_1_n_2(self):
        pybullet.N = 2

        proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])

        with self.assertRaises(ValueError):
            proof_B,state = pybullet.prove_B(state,Scalar(0),proof.z)

    # Evil dealer with 1 input, challenge z=0
    def test_invalid_z0_m_1_n_2(self):
        pybullet.N = 2

        proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])

        with self.assertRaises(ValueError):
            proof_B,state = pybullet.prove_B(state,proof.y,Scalar(0))

    # Evil dealer with 1 input, challenge x=0
    def test_invalid_x0_m_1_n_2(self):
        pybullet.N = 2

        proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)

        with self.assertRaises(ValueError):
            proof_C = pybullet.prove_C(state,Scalar(0))

    # Valid proof with 2 inputs
    def test_prove_verify_m_2_n_4(self):
        M = 2
        pybullet.N = 4

        proofs_A = []
        proofs_B = []
        proofs_C = []
        states = [] # not available to the dealer

        for k in range(M):
            proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),k)
            proofs_A.append(proof_A)
            states.append(state)
        proof = pybullet.aggregate_A(proofs_A)
        for k in range(M):
            proof_B,state = pybullet.prove_B(states[k],proof.y,proof.z)
            proofs_B.append(proof_B)
            states[k] = state
        proof = pybullet.aggregate_B(proofs_B,proof)
        for k in range(M):
            proof_C = pybullet.prove_C(states[k],proof.x)
            proofs_C.append(proof_C)
            states[k] = state
        proof = pybullet.aggregate_C(proofs_C,proof)

        pybullet.verify([proof])

    # Evil dealer with 2 inputs, same player index
    def test_invalid_repeat_index_m_2_n_2(self):
        M = 2
        pybullet.N = 2

        proofs_A = []
        proofs_B = []
        proofs_C = []
        states = [] # not available to the dealer

        for k in range(M):
            proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
            proofs_A.append(proof_A)
            states.append(state)
        proof = pybullet.aggregate_A(proofs_A)
        for k in range(M):
            proof_B,state = pybullet.prove_B(states[k],proof.y,proof.z)
            proofs_B.append(proof_B)
            states[k] = state
        proof = pybullet.aggregate_B(proofs_B,proof)
        for k in range(M):
            proof_C = pybullet.prove_C(states[k],proof.x)
            proofs_C.append(proof_C)
            states[k] = state
        proof = pybullet.aggregate_C(proofs_C,proof)

        with self.assertRaises(ArithmeticError):
            pybullet.verify([proof])

for test in [TestBulletOps,TestBullet]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
