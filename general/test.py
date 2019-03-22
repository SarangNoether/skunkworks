# Basic test suite for CLSAG

import dumb25519
from dumb25519 import *
import clsag
from clsag import *
import unittest

# Sign and verify with arbitrary index, inputs, and ring size
def build(l,m,n):
    p = [random_scalar()]*m
    P = []
    for i in range(n):
        P.append([])
        for j in range(m):
            if i == l:
                P[i].append(G*p[j])
            else:
                P[i].append(random_point())
    M = 'Test message'

    sig = sign(M,p,P)
    verify(M,P,sig)

class TestValidSignatures(unittest.TestCase):
    def test_valid(self):
        build(0,1,1)
        build(0,1,2)
        build(1,1,2)
        build(0,1,3)
        build(1,1,3)
        build(2,1,3)

        build(0,2,1)
        build(0,2,2)
        build(1,2,2)
        build(0,2,3)
        build(1,2,3)
        build(2,2,3)

class TestTransaction(unittest.TestCase):
    # Type full: 1 in, 2 out
    def test_full_1_2(self):
        n = 3 # ring size

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
        C[1] = C_in-C_out[0]-C_out[1]

        p = [random_scalar(),z]
        P = [[random_point(),C[0]],[G*p[0],C[1]],[random_point(),C[2]]]

        # Generate signature and verify
        M = 'Transaction message'
        sig = sign(M,p,P)
        verify(M,P,sig)

    # Type full: 2 in, 2 out
    def test_full_2_2(self):
        n = 3 # ring size

        # Generate input and output commitments
        amounts_in = [Scalar(2),Scalar(3)]
        blinders_in = [random_scalar()]*2
        amounts_out = [Scalar(4),Scalar(1)]
        blinders_out = [random_scalar()]*2

        C_in = [H*amounts_in[i] + G*blinders_in[i] for i in range(2)]
        C_out = [H*amounts_out[i] + G*blinders_out[i] for i in range(2)]
        z = blinders_in[0] + blinders_in[1] - blinders_out[0] - blinders_out[1]

        # Construct commitment offsets and keys
        C = [random_point()-C_out[0]-C_out[1]]*n
        C[1] = C_in[0]+C_in[1]-C_out[0]-C_out[1]

        p = [random_scalar(),random_scalar(),z]
        P = [[random_point(),random_point(),C[0]],[G*p[0],G*p[1],C[1]],[random_point(),random_point(),C[2]]]

        # Generate signature and verify
        M = 'Transaction message'
        sig = sign(M,p,P)
        verify(M,P,sig)

    # Type simple: 1 in, 2 out
    def test_simple_1_2(self):
        n = 3 # ring size

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
        C[1] = C_in-C_pseudo

        p = [random_scalar(),z]
        P = [[random_point(),C[0]],[G*p[0],C[1]],[random_point(),C[2]]]

        # Generate signature and verify
        M = 'Transaction message'
        sig = sign(M,p,P)
        verify(M,P,sig)
        
        if not C_pseudo-C_out[0]-C_out[1] == Z:
            raise ArithmeticError('Failed transaction balance check!')

for test in [TestValidSignatures,TestTransaction]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
