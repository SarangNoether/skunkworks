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

class TestValidProofs(unittest.TestCase):
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

class TestBadChallenges(unittest.TestCase):
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

class TestBadIndex(unittest.TestCase):
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

class TestBadValues(unittest.TestCase):
    # Invalid proof with negative value
    def test_bad_value_negative(self):
        pybullet.N = 2

        proof_A,state = pybullet.prove_A(Scalar(-1),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)
        proof_C = pybullet.prove_C(state,proof.x)
        proof = pybullet.aggregate_C([proof_C],proof)

        with self.assertRaises(ArithmeticError):
            pybullet.verify([proof])

    # Invalid proof with large value
    def test_bad_value_large(self):
        pybullet.N = 2

        proof_A,state = pybullet.prove_A(Scalar(2**pybullet.N),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)
        proof_C = pybullet.prove_C(state,proof.x)
        proof = pybullet.aggregate_C([proof_C],proof)

        with self.assertRaises(ArithmeticError):
            pybullet.verify([proof])

class TestValidBatch(unittest.TestCase):
    # Valid batch of two single-output proofs
    def test_valid_batch_m_1_m_1_n_4(self):
        pybullet.N = 4
        proofs = []

        for i in range(2):
            proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
            proof = pybullet.aggregate_A([proof_A])
            proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
            proof = pybullet.aggregate_B([proof_B],proof)
            proof_C = pybullet.prove_C(state,proof.x)
            proofs.append(pybullet.aggregate_C([proof_C],proof))

        pybullet.verify(proofs)

    # Valid batch of a single-output and 2-output proof
    def test_valid_batch_m_1_m_2_n_4(self):
        pybullet.N = 4
        M = 2
        proofs = []

        # single-output proof
        proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)
        proof_C = pybullet.prove_C(state,proof.x)
        proofs.append(pybullet.aggregate_C([proof_C],proof))

        # 2-output proof
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
        proofs.append(pybullet.aggregate_C(proofs_C,proof))

        pybullet.verify(proofs)

class TestInvalidBatch(unittest.TestCase):
    # Invalid batch of two single-output proofs
    def test_invalid_batch_m_1_m_1_n_4(self):
        pybullet.N = 4
        proofs = []

        # Valid proof
        proof_A,state = pybullet.prove_A(Scalar(random.randint(0,2**pybullet.N-1)),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)
        proof_C = pybullet.prove_C(state,proof.x)
        proofs.append(pybullet.aggregate_C([proof_C],proof))

        # Invalid proof (bad value)
        proof_A,state = pybullet.prove_A(Scalar(2**pybullet.N),random_scalar(),0)
        proof = pybullet.aggregate_A([proof_A])
        proof_B,state = pybullet.prove_B(state,proof.y,proof.z)
        proof = pybullet.aggregate_B([proof_B],proof)
        proof_C = pybullet.prove_C(state,proof.x)
        proofs.append(pybullet.aggregate_C([proof_C],proof))

        with self.assertRaises(ArithmeticError):
            pybullet.verify(proofs)

class TestKnownProofs(unittest.TestCase):
    # Test a proof manually
    def test_v_2_n_2_k_0(self):
        # A-proof
        seed = 1 # arbitrary
        v = Scalar(2)
        gamma = Scalar(23579) # abitrary commitment blinder
        pybullet.N = 2

        pybullet.set_seed(seed)
        alpha = random_scalar()
        sL = ScalarVector([random_scalar()]*pybullet.N)
        sR = ScalarVector([random_scalar()]*pybullet.N)
        rho = random_scalar()

        # fixed points
        H = hash_to_point('pybullet H')
        Gi = [hash_to_point('pybullet Gi '+str(i)) for i in range(pybullet.N)]
        Hi = [hash_to_point('pybullet Hi '+str(i)) for i in range(pybullet.N)]

        # proof elements
        A = (G*alpha + Gi[1] - Hi[0])*Scalar(8).invert()
        S = (G*rho + Gi[0]*sL[0] + Gi[1]*sL[1] + Hi[0]*sR[0] + Hi[1]*sR[1])*Scalar(8).invert()

        proof_A,state = pybullet.prove_A(v,gamma,0,seed=seed)
        self.assertEqual(proof_A.A,A)
        self.assertEqual(proof_A.S,S)

        # B-proof
        seed = 2 # arbitrary
        pybullet.set_seed(seed)
        y = Scalar(8675309) # arbitrary nonzero challenge
        z = Scalar(3141592) # arbitrary nonzero challenge

        l0 = ScalarVector([-z,Scalar(1)-z])
        l1 = sL
        r0 = ScalarVector([Scalar(-1)+z+z**2,y*z+Scalar(2)*z**2])
        r1 = ScalarVector([sR[0],y*sR[1]])

        t1 = l0**r1 + l1**r0
        t2 = l1**r1

        tau1 = random_scalar()
        tau2 = random_scalar()
        T1 = (H*t1 + G*tau1)*Scalar(8).invert()
        T2 = (H*t2 + G*tau2)*Scalar(8).invert()

        proof_B,state = pybullet.prove_B(state,y,z,seed=seed)
        self.assertEqual(proof_B.T1,T1)
        self.assertEqual(proof_B.T2,T2)

        # C-proof
        seed = 3 # arbitrary
        pybullet.set_seed(seed)
        x = Scalar(2718281) # arbitrary nonzero challenge

        taux = tau2*x**2 + tau1*x + z**2*gamma
        mu = alpha + rho*x
        l = l0 + l1*x
        r = r0 + r1*x

        proof_C = pybullet.prove_C(state,x,seed=seed)
        self.assertEqual(proof_C.taux,taux)
        self.assertEqual(proof_C.mu,mu)
        self.assertEqual(proof_C.l[0],l[0])
        self.assertEqual(proof_C.l[1],l[1])
        self.assertEqual(proof_C.r[0],r[0])
        self.assertEqual(proof_C.r[1],r[1])

        # inner product
        pybullet.cache = x
        pybullet.mash(taux)
        pybullet.mash(mu)
        pybullet.mash(l**r)
        x_ip = pybullet.cache

        L = (Gi[1]*l[0] + Hi[0]*r[1] + H*(l[0]*r[1]*x_ip))*Scalar(8).invert()
        R = (Gi[0]*l[1] + Hi[1]*(r[0]*y.invert()) + H*(l[1]*r[0]*x_ip))*Scalar(8).invert()
        pybullet.mash(L)
        pybullet.mash(R)
        w = pybullet.cache

        a = l[0]*w + l[1]*w.invert()
        b = r[0]*w.invert() + r[1]*w

        # check against final proof
        proof = pybullet.aggregate_A([proof_A])
        proof.y = y
        proof.z = z
        proof = pybullet.aggregate_B([proof_B],proof)
        proof.x = x
        proof = pybullet.aggregate_C([proof_C],proof)

        self.assertEqual(proof.t,l**r)
        self.assertEqual(proof.a,a)
        self.assertEqual(proof.b,b)
        self.assertEqual(proof.L[0],L)
        self.assertEqual(proof.R[0],R)

for test in [TestBulletOps,TestValidProofs,TestBadChallenges,TestBadIndex,TestBadValues,TestValidBatch,TestInvalidBatch,TestKnownProofs]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
