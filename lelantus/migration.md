Suppose that Alice wishes to migrate an output `P = pG` to the Lelantus pool, where the associated commitment to `P` is `C = vG + aH`; that is, the output has value `v` and commitment mask `a`.

Alice gathers a ring of possible spends `{P_i}` such that `P_l = P` for some `l`. Each has an associated commitment `{C_i = v_iG + a_iH}.` She constructs an intermediate output `C' = vG + bH,` where `b` is a random mask. Alice assembles the following two-dimensional ring to sign with MLSAG:

    {(P_1,C_1-C'),
    ...
    (P,C-C'),
    ...
    (P_n,C_n-C')}

As with any correct MLSAG signature, Alice knows the private key pair `(p,a-b)`, which proves both control of the spent output and transaction balance.

Now, Alice forms a new Lelantus commitment `D = vG + rH + sH'`, where `H'` is a fixed generator that is DL-independent from `G` and `H`, `r` is a random mask, and `s` is the coin serial number. She constructs a generalized Schnorr proof of knowledge:

    D - C' = (vG + rH + sH') - (vG + bH)
           = (r - b)H + sH'

That is, Alice proves in zero knowledge that she knows the discrete logarithms of both `H` and `H'` for the commitment difference. Further, she implicitly proves that `D` and `C'` (and, by extension, `C`) share the same value.

The use of the intermediate commitment is important, since later spending of `D` will reveal the serial number `s`. An observer must not be able to use information from an MLSAG to identify when such a commitment is included in a later spend transaction.
