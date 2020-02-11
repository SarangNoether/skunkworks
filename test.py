# Tests for spend proofs

import unittest
from dumb25519 import *
from proof import *

class TestProofs(unittest.TestCase):
    def test_spend_proof(self):
        address = Address()
        coin = Coin(address)
        coin.recover(address)
        proof = SpendProof(coin,address,STATUS_SPEND)
        self.assertTrue(proof.verify(coin,address,STATUS_SPEND,coin.I))

    def test_non_spend_proof(self):
        address = Address()
        coin = Coin(address)
        coin.recover(address)
        I = random_point()
        proof = SpendProof(coin,address,STATUS_NON_SPEND,I)
        self.assertTrue(proof.verify(coin,address,STATUS_NON_SPEND,I))

unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(TestProofs))
