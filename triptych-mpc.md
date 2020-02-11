# Triptych MPC

This document briefly and informally describes how to produce an `n`-of-`n` multisignature using the [Triptych](https://github.com/SarangNoether/skunkworks/tree/triptych) proving system.

Since a Tiptych transaction consists of multiple separate spend proofs with outputs known to all signers, it suffices to describe how to allow a group of `n` signers, each of whom has an additive share `r_i` of the signing secret key `r`, to collaboratively produce a proof.
We note that the following method has not been formally analyzed for security; in particular, we assume only honest-but-curious players, who follow the multiparty computation (MPC) protocol, but may be interested to learn other players' secret data while doing so.
Such a security model might also assume that up to `n - 1` of the players collude at the end of the protocol to learn the remaining player's secrets.
It should be assumed insecure in the presence of malicious players who can deviate arbitrarily from the protocol.

We assume that a signing private key has been produced using the method of [Goodell and Noether](https://eprint.iacr.org/2018/774), which uses [MuSig](https://eprint.iacr.org/2018/068)-style key aggregation applied to one-time addresses.
The approach follows two separate goals: one is to derive the shared key image, which is of the form `1/r*U` for a globally-fixed group element `U`.
A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified for this purpose, requiring a many-to-many share derivation described elsewhere.
The second goal is simply to compute a quantity that is linear in the shared secret key `r`; by assuming only honest-but-curious players, this is straightforward and only requires communication with a designated player, here called the dealer, who is unable to learn any other players' secret shares.

Note that verification of a Triptych MPC transaction necessarily proceeds identically to a standard transaction.


## Proof

To proceed with the Triptych proof, each player `i` selects a random set of scalars `{rho_ij}` for `j = 0..m-1`, computes `{rho_ij*G}` and `{rho_ij*J}`, and sends the latter two sets of group elements to the dealer.
For all `j`, the dealer computes `rho_j*G := rho_1j*G + ... + rho_nj*G` and `rho_j*J := rho_1j*J + ... + rho_nj*J`, and uses these values to compute each `X_j` and `Y_j` in the proof.
The dealer computes the Fiat-Shamir transcript challenge `x` and sends it to all players.
Each player `i` then computes `z_i := r_i*x^m - rho_i0*x^0 - ... - rho_i(m-1)*x^(m-1)` and sends it to the dealer.
The dealer finishes the proof, setting `z := z_1 + ... + z_n + mu*s*x^m`.
