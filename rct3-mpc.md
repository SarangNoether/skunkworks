# RingCT 3.0 MPC

This document briefly and informally describes how to produce an `n`-of-`n` multisignature using the [RingCT3.0](https://eprint.iacr.org/2019/508) (RCT3) proving system.
Note that this process assumes the older single-input version of the proving system, with the appropriate exploit mitigations [applied](https://github.com/SarangNoether/skunkworks/tree/rct3/rct3-single).

Since an RCT3 transaction consists of multiple separate spend proofs with outputs known to all signers, it suffices to describe how to allow a group of `n` signers, each of whom has an additive share `r_i` of the signing secret key `r`, to collaboratively produce a proof.
We note that the following method has not been formally analyzed for security; in particular, we assume only honest-but-curious players, who follow the multiparty computation (MPC) protocol, but may be interested to learn other players' secret data while doing so.
Such a security model might also assume that up to `n - 1` of the players collude at the end of the protocol to learn the remaining player's secrets.
It should be assumed insecure in the presence of malicious players who can deviate arbitrarily from the protocol.

We assume that a signing private key has been produced using the method of [Goodell and Noether](https://eprint.iacr.org/2018/774), which uses [MuSig](https://eprint.iacr.org/2018/068)-style key aggregation applied to one-time addresses.
The approach follows two separate goals: one is to derive the shared key image, which is of the form `1/r*U` for a globally-fixed group element `U`.
A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified for this purpose, requiring a many-to-many share derivation described elsewhere.
The second goal is simply to compute a quantity that is linear in the shared secret key `r`; by assuming only honest-but-curious players, this is straightforward and only requires communication with a designated player, here called the dealer, who is unable to learn any other players' secret shares.

Note that verification of an RCT3 MPC transaction necessarily proceeds identically to a standard transaction.


## Proof

To proceed with the RCT3 proof, each player `i` selects random `r'_i`, computes `r'_i*G` and `r'_i*U'`, and sends the latter two quantities to the dealer.
The dealer computes `r_sk*G := r'_1*G + ... + r'_n*G` and uses it to compute the value `S_1` for the proof.
The dealer computes the value `S_3 := r'_1*U' + ... + r'_n*U'` for the proof.
The dealer proceeds, computing the Fiat-Shamir transcript challenge `x` and sending it to all players.
Each player `i` then computes `z_i := r'_i + r_i*x` and sends it to the dealer.
The dealer finishes the proof, setting `z_sk := z_1 + ... + z_n`.
