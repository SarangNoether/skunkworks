# RingCT 3.0 MPC

This document briefly and informally describes how to produce an `n`-of-`n` multisignature using the [RingCT3.0](https://eprint.iacr.org/2019/508) (RCT3) proving system.
Note that this process assumes the older single-input version of the proving system, with the appropriate exploit mitigations [applied](https://github.com/SarangNoether/skunkworks/tree/rct3).

Since an RCT3 transaction consists of multiple separate spend proofs with outputs known to all signers, it suffices to describe how to allow a group of `n` signers, each of whom has an additive share `r_i` of the signing secret key `r`, to collaboratively produce a proof.
We note that the following method has not been formally analyzed for security; in particular, we assume only honest-but-curious players, who follow the multiparty computation (MPC) protocol, but may be interested to learn other players' secret data while doing so.
Such a security model might also assume that up to `n - 1` of the players collude at the end of the protocol to learn the remaining player's secrets.
It should be assumed insecure in the presence of malicious players who can deviate arbitrarily from the protocol.

We assume that a signing private key has been produced using the method of [Goodell and Noether](https://eprint.iacr.org/2018/774), which uses [MuSig](https://eprint.iacr.org/2018/068)-style key aggregation applied to one-time addresses.
The approach follows two separate goals: one is to derive the shared key image, which is of the form `1/r*U` for a globally-fixed group element `U`.
A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified for this purpose, requiring a many-to-many share derivation that we describe below.
The second goal is simply to compute a quantity that is linear in the shared secret key `r`; by assuming only honest-but-curious players, this is straightforward and only requires communication with a designated player, here called the dealer, who is unable to learn any other players' secret shares.

Note that verification of an RCT3 MPC transaction necessarily proceeds identically to a standard transaction.


## Key image

Suppose we have `n` honest-but-curious players in the MPC, one of whom is arbitrarily selected as a dealer.
Each player `i` holds a secret share `r_i` of the secret key `r`, so that `r_1 + ... + r_n = r`.
Further, each player `i` holds a Paillier secret key, the public key of which has previously been distributed to all other players.

Each player `i` chooses a random scalar `g_i` and sets `G_i := g_i*U`.
Player `i` then computes the quantity `c_i := E_i(x_i)`, where `E_i` represents Paillier encryption using the public key for player `i`, and sends `c_i` to each player `j`.
Player `j` chooses a random scalar `b_ji` for each such receipt.
Player `j` computes `c_j := g_j*E_i(x_i) + E_i(-b_ji)` using Paillier homomorphicity, and sends `c_j` back to player `i`.
Player `i` sets `a_ij := D_i(c_j)`, where `D_i` represents Paillier decryption using the secret key for player `i`.

After all players have completed this exchange, each player `i` holds scalars `a_ij` and `b_ij` for each other player `j`.
Each player `i` computes `d_i := x_i*g_i + Sum[a_ij + b_ij]`, where the sum is taken over all other `j`, and sends `d_i` and `G_i` to the dealer.

The dealer computes `d := d_1 + ... + d_n`.
The dealer then computes `U' := 1/d*(G_1 + ... G_n)`; this is the shared key image `1/r*U`, which the dealer sends to all players.

Insecure example code demonstrating this computation is [available](https://github.com/SarangNoether/skunkworks/blob/inverse-mpc/inverse.py), but should not be used in production.


## Proof

To proceed with the RCT3 proof, each player `i` selects random `r'_i`, computes `r'_i*G` and `r'_i*U'`, and sends the latter two quantities to the dealer.
The dealer computes `r_sk*G := r'_1*G + ... + r'_n*G` and uses it to compute the value `S_1` for the proof.
The dealer computes the value `S_3 := r'_1*U' + ... + r'_n*U'` for the proof.
The dealer proceeds, computing the Fiat-Shamir transcript challenge `x` and sending it to all players.
Each player `i` then computes `z_i := r'_i + r_i*x` and sends it to the dealer.
The dealer finishes the proof, setting `z_sk := z_1 + ... + z_n`.
