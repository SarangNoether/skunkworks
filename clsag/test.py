# Basic test suite for CLSAG

import dumb25519
from dumb25519 import *
import clsag
from clsag import *
import unittest

class TestValidSignatures(unittest.TestCase):
    def test_n_1(self):
        p = random_scalar()
        P = [G*p]
        z = random_scalar()
        C = [G*z]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C)
        self.assertEqual(verify(M,P,C,sig),None)

    def test_n_2_l_0(self):
        p = random_scalar()
        P = [G*p,random_point()]
        z = random_scalar()
        C = [G*z,random_point()]
        M = 'Test message'
        seed = random_scalar()
        
        sig = sign(M,p,P,z,C,seed)
        self.assertEqual(verify(M,P,C,sig,seed),0)

        sig = sign(M,p,P,z,C)
        self.assertEqual(verify(M,P,C,sig),None)

    def test_n_2_l_1(self):
        p = random_scalar()
        P = [random_point(),G*p]
        z = random_scalar()
        C = [random_point(),G*z]
        M = 'Test message'
        seed = random_scalar()
        
        sig = sign(M,p,P,z,C,seed)
        self.assertEqual(verify(M,P,C,sig,seed),1)

        sig = sign(M,p,P,z,C)
        self.assertEqual(verify(M,P,C,sig),None)

class TestBadPoints(unittest.TestCase):
    def test_n_1_bad_P(self):
        p = random_scalar()
        P = [random_point()]
        z = random_scalar()
        C = [G*z]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C,index=0)
        with self.assertRaises(ArithmeticError):
            verify(M,P,C,sig)

    def test_n_1_bad_C(self):
        p = random_scalar()
        P = [G*p]
        z = random_scalar()
        C = [random_point()]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C,index=0)
        with self.assertRaises(ArithmeticError):
            verify(M,P,C,sig)

    def test_n_2_l_0_bad_P(self):
        p = random_scalar()
        P = [random_point(),random_point()]
        z = random_scalar()
        C = [G*z,random_point()]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C,index=0)
        with self.assertRaises(ArithmeticError):
            verify(M,P,C,sig)

    def test_n_2_l_0_bad_C(self):
        p = random_scalar()
        P = [G*p,random_point()]
        z = random_scalar()
        C = [random_point(),random_point()]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C,index=0)
        with self.assertRaises(ArithmeticError):
            verify(M,P,C,sig)

    def test_n_2_index_swap_0(self):
        p = random_scalar()
        P = [G*p,random_point()]
        z = random_scalar()
        C = [random_point(),G*z]
        M = 'Test message'

        sig = sign(M,p,P,z,C,index=0)
        with self.assertRaises(ArithmeticError):
            verify(M,P,C,sig)

    def test_n_2_index_swap_1(self):
        p = random_scalar()
        P = [G*p,random_point()]
        z = random_scalar()
        C = [random_point(),G*z]
        M = 'Test message'

        sig = sign(M,p,P,z,C,index=1)
        with self.assertRaises(ArithmeticError):
            verify(M,P,C,sig)

class TestTransaction(unittest.TestCase):
    # Type full: 1 in, 2 out
    def test_full_1_2(self):
        H = hash_to_point('clsag H')
        n = 3 # ring size
        l = 1 # secret ring index

        # Generate input and output commitments
        amount_in = Scalar(3)
        blinder_in = random_scalar()
        amounts_out = [Scalar(2),Scalar(1)]
        blinders_out = [random_scalar()]*2

        C_in = H*amount_in + G*blinder_in
        C_out = [H*amounts_out[i] + G*blinders_out[i] for i in range(2)]
        z = blinder_in - blinders_out[0] - blinders_out[1]

        # Construct commitment offsets and keys
        C = [random_point()-C_out[0]-C_out[1]]*n
        C[l] = C_in-C_out[0]-C_out[1]

        p = random_scalar()
        P = [random_point()]*n
        P[l] = G*p

        # Generate signature and verify
        M = 'Transaction message'
        sig = sign(M,p,P,z,C)
        verify(M,P,C,sig)

    # Type simple: 1 in, 2 out
    def test_simple_1_2(self):
        H = hash_to_point('clasg H')
        n = 3 # ring size
        l = 1 # secret ring index

        # Generate input and output commitments
        amount_in = Scalar(3)
        blinder_in = random_scalar()
        amounts_out = [Scalar(2),Scalar(1)]
        blinders_out = [random_scalar()]*2

        C_in = H*amount_in + G*blinder_in
        C_out = [H*amounts_out[i] + G*blinders_out[i] for i in range(2)]

        blinder_pseudo_in = blinders_out[0]+blinders_out[1]
        C_pseudo = H*amount_in + G*blinder_pseudo_in
        z = blinder_in-blinder_pseudo_in

        C = [random_point()-C_pseudo]*n
        C[l] = C_in-C_pseudo

        p = random_scalar()
        P = [random_point()]*n
        P[l] = G*p

        # Generate signature and verify
        M = 'Transaction message'
        sig = sign(M,p,P,z,C)
        verify(M,P,C,sig)
        
        if not C_pseudo-C_out[0]-C_out[1] == Z:
            raise ArithmeticError('Failed transaction balance check!')

for test in [TestValidSignatures,TestBadPoints,TestTransaction]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
