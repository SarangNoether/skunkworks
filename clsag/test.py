# Basic test suite for CLSAG

import dumb25519
from dumb25519 import random_scalar, random_point, G
import clsag
from clsag import sign, verify
import unittest

class TestValidSignatures(unittest.TestCase):
    def test_n_1(self):
        p = random_scalar()
        P = [G*p]
        z = random_scalar()
        C = [G*z]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C)
        verify(M,P,C,sig)

    def test_n_2_l_0(self):
        p = random_scalar()
        P = [G*p,random_point()]
        z = random_scalar()
        C = [G*z,random_point()]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C)
        verify(M,P,C,sig)

    def test_n_2_l_1(self):
        p = random_scalar()
        P = [random_point(),G*p]
        z = random_scalar()
        C = [random_point(),G*z]
        M = 'Test message'
        
        sig = sign(M,p,P,z,C)
        verify(M,P,C,sig)

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

for test in [TestValidSignatures,TestBadPoints]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
