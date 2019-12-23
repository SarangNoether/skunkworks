# RingCT 3.0 aggregate MPC

This document briefly and informally describes how to produce an `n`-of-`n` multisignature using the [RingCT3.0](https://eprint.iacr.org/2019/508) (RCT3) proving system.
Note that this process assumes the newer aggregated-input [version](https://github.com/SarangNoether/skunkworks/tree/rct3/rct3-multi) of the proving system.

Since an RCT3 transaction consists of a single spend proof with outputs known to all signers, we describe how to allow a group of `n` signers, each of whom has an additive share `(r_i)_k` of each element in a set of `M` signing secret keys `{r_k}`, to collaboratively produce a proof.
We note that the following method has not been formally analyzed for security; in particular, we assume only honest-but-curious players, who follow the multiparty computation (MPC) protocol, but may be interested to learn other players' secret data while doing so.
Such a security model might also assume that up to `n - 1` of the players collude at the end of the protocol to learn the remaining player's secrets.
It should be assumed insecure in the presence of malicious players who can deviate arbitrarily from the protocol.

We assume that signing private keys have been produced using the method of [Goodell and Noether](https://eprint.iacr.org/2018/774), which uses [MuSig](https://eprint.iacr.org/2018/068)-style key aggregation applied to one-time addresses.
The approach follows two separate goals: one is to derive all shared key images, each of which is of the form `1/r_k*U` for a globally-fixed group element `U`.
A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified for this purpose, requiring a many-to-many share derivation that we describe below.
The second goal is simply to compute a quantity that is linear in each shared secret key `r_k`; by assuming only honest-but-curious players, this is straightforward and only requires communication with a designated player, here called the dealer, who is unable to learn any other players' secret shares.

Note that verification of an RCT3 MPC transaction necessarily proceeds identically to a standard transaction.


## Key images

Suppose we have `n` honest-but-curious players in the MPC, one of whom is arbitrarily selected as a dealer.
Each player `i` holds a secret share `(r_i)_k` of each of `M` secret keys `r_k`, so that `(r_1)_k + ... + (r_n)_k = r_k`.
Further, each player `i` holds a Paillier secret key, the public key of which has previously been distributed to all other players.

Each player `i` chooses `M` random scalars `{(g_i)_k}` and sets `(G_i)_k := (g_i)_k*U`.
Player `i` then computes (for all `k`) the quantity `(c_i)_k := E_i((r_i)_k)`, where `E_i` represents Paillier encryption using the public key for player `i`, and sends all `{(c_i)_k}` to each player `j`.
Player `j` chooses a random scalar `(b_ji)_k` for each such receipt.
Player `j` computes each `(c_j)_k := (g_j)_k*E_i((r_i)_k) + E_i(-(b_ji)_k)` using Paillier homomorphicity, and sends all `{(c_j)_k}` back to player `i`.
Player `i` sets `(a_ij)_k := D_i((c_j)_k)`, where `D_i` represents Paillier decryption using the secret key for player `i`.

After all players have completed this exchange, each player `i` holds scalars `{(a_ij)_k}` and `{(b_ij)_k}` for each other player `j`.
Each player `i` computes `(d_i)_k := (r_i)_k*(g_i)_k + Sum[(a_ij)_k + (b_ij)_k]`, where the sum is taken over all other `j`, and sends `{(d_i)_k}` and `{(G_i)_k}` to the dealer.

The dealer computes `d_k := (d_1)_k + ... + (d_n)_k`.
The dealer then computes `U'_k := 1/d_k*((G_1)_k + ... (G_n)_k)`; this is the shared key image `1/r_k*U`; the dealer sends the set `{U'_k}` to all players.

Insecure example code demonstrating a simplified computation is [available](https://github.com/SarangNoether/skunkworks/blob/inverse-mpc/inverse.py), but should not be used in production.


## Proof

To proceed with the RCT3 proof, each player `i` selects random `{(r'_i)_k}`, computes `(S_1)_i := Sum_k[(r'_i)_k*d_0^k]*G` and `(S_3)_i := Sum_k[(r'_i)_k*d_0^k*U'_k]`, and sends the latter two quantities to the dealer.
The dealer computes `Sum_i[(S_1)_i]` and uses this to compute the value `S_1` for the proof.
The dealer computes `S_3 := Sum_i[(S_3)_i]`.
The dealer proceeds, computing the Fiat-Shamir transcript challenge `x` and sending it to all players.
Each player `i` then computes each `(z_i)_k := (r'_i)_k + (r_i)_k*x` and sends it to the dealer.
The dealer finishes the proof, setting each `(z_sk)_k := (z_1)_k + ... + (z_n)_k`.
