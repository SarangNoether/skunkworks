# RingCT 3.0 aggregate MPC

This document briefly and informally describes how to produce an `n`-of-`n` multisignature using the [RingCT3.0](https://eprint.iacr.org/2019/508) (RCT3) proving system.
Note that this process assumes the newer aggregated-input [version](https://github.com/SarangNoether/skunkworks/tree/rct3/rct3-multi) of the proving system.

Since an RCT3 transaction consists of a single spend proof with outputs known to all signers, we describe how to allow a group of `n` signers, each of whom has an additive share `(r_i)_k` of each element in a set of `M` signing secret keys `{r_k}`, to collaboratively produce a proof.
We note that the following method has not been formally analyzed for security; in particular, we assume only honest-but-curious players, who follow the multiparty computation (MPC) protocol, but may be interested to learn other players' secret data while doing so.
Such a security model might also assume that up to `n - 1` of the players collude at the end of the protocol to learn the remaining player's secrets.
It should be assumed insecure in the presence of malicious players who can deviate arbitrarily from the protocol.

We assume that signing private keys have been produced using the method of [Goodell and Noether](https://eprint.iacr.org/2018/774), which uses [MuSig](https://eprint.iacr.org/2018/068)-style key aggregation applied to one-time addresses.
The approach follows two separate goals: one is to derive all shared key images, each of which is of the form `1/r_k*U` for a globally-fixed group element `U`.
A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified for this purpose, requiring a many-to-many share derivation described elsewhere.
The second goal is simply to compute a quantity that is linear in each shared secret key `r_k`; by assuming only honest-but-curious players, this is straightforward and only requires communication with a designated player, here called the dealer, who is unable to learn any other players' secret shares.

Note that verification of an RCT3 MPC transaction necessarily proceeds identically to a standard transaction.


## Proof

To proceed with the RCT3 proof, each player `i` selects random `{(r'_i)_k}`, computes `(S_1)_i := Sum_k[(r'_i)_k*d_0^k]*G` and `(S_3)_i := Sum_k[(r'_i)_k*d_0^k*U'_k]`, and sends the latter two quantities to the dealer.
The dealer computes `Sum_i[(S_1)_i]` and uses this to compute the value `S_1` for the proof.
The dealer computes `S_3 := Sum_i[(S_3)_i]`.
The dealer proceeds, computing the Fiat-Shamir transcript challenge `x` and sending it to all players.
Each player `i` then computes each `(z_i)_k := (r'_i)_k + (r_i)_k*x` and sends it to the dealer.
The dealer finishes the proof, setting each `(z_sk)_k := (z_1)_k + ... + (z_n)_k`.
