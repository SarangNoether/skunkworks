# Test suite for discrete log proof of equality

from discrete import *
import dumb25519
import dumb448
import unittest

class TestDecomposition(unittest.TestCase):
    # test decompositions of small values
    def test_nary(self):
        assert nary(0,2) == [0]
        assert nary(1,2) == [1]
        assert nary(2,2) == [0,1]
        assert nary(2,3) == [2]
        assert nary(3,2) == [1,1]
        assert nary(3,3) == [0,1]

    # test bad parameters
    def test_bad_nary(self):
        with self.assertRaises(ArithmeticError):
            nary(-1,2)
        with self.assertRaises(ArithmeticError):
            nary(1,0)

class TestValidProofs(unittest.TestCase):
    # test a few simple valid proofs for small values
    def test_0(self):
        verify(prove(0))

    def test_1(self):
        verify(prove(1))

    def test_2(self):
        verify(prove(2))

class TestBadProofs(unittest.TestCase):
    # each x is out of range
    def test_bad_x(self):
        with self.assertRaises(ValueError):
            verify(prove(max_x))
        with self.assertRaises(ValueError):
            verify(prove(max_x+1))
        with self.assertRaises(ValueError):
            verify(prove(-1))
    
    def test_bad_hash(self):
        # xG is replaced with a random point
        proof = prove(2)
        proof.xG = dumb25519.random_point()
        with self.assertRaises(ArithmeticError):
            verify(proof)

        # xH is replaced with a random point
        proof = prove(2)
        proof.xH = dumb448.random_point()
        with self.assertRaises(ArithmeticError):
            verify(proof)

    def test_bad_mix_0_1(self):
        proof_G = prove(0)
        proof_H = prove(1)
        
        # each group has a different 1-bit discrete log (0 for G, 1 for H)
        proof = Proof(proof_G.xG,proof_H.xH,proof_G.C_G,proof_H.C_H,proof_G.e0_G,proof_H.e0_H,proof_G.a0,proof_G.a1,proof_H.b0,proof_H.b1)
        with self.assertRaises(ArithmeticError):
            verify(proof)

    def test_bad_mix_1_0(self):
        proof_G = prove(1)
        proof_H = prove(0)
        
        # each group has a different 1-bit discrete log (1 for G, 0 for H)
        proof = Proof(proof_G.xG,proof_H.xH,proof_G.C_G,proof_H.C_H,proof_G.e0_G,proof_H.e0_H,proof_G.a0,proof_G.a1,proof_H.b0,proof_H.b1)
        with self.assertRaises(ArithmeticError):
            verify(proof)

tests = [TestDecomposition,TestValidProofs,TestBadProofs]
for test in tests:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
