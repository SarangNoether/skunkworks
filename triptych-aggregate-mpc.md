# Triptych aggregate MPC

This document briefly and informally describes how to produce an `n`-of-`n` multisignature using the [Triptych](https://github.com/SarangNoether/skunkworks/tree/triptych) proving system. Note that this process assumes the newer aggregated-input version of the proving system.

Since a Tiptych transaction consists of a single spend proof with outputs known to all signers, we describe how to allow a group of `n` signers, each of whom has an additive share `(r_i)_k` of each element in a set of `M` signing secret keys `{r_k}`, to collaboratively produce a proof.
We note that the following method has not been formally analyzed for security; in particular, we assume only honest-but-curious players, who follow the multiparty computation (MPC) protocol, but may be interested to learn other players' secret data while doing so.
Such a security model might also assume that up to `n - 1` of the players collude at the end of the protocol to learn the remaining player's secrets.
It should be assumed insecure in the presence of malicious players who can deviate arbitrarily from the protocol.

We assume that signing private keys have been produced using the method of [Goodell and Noether](https://eprint.iacr.org/2018/774), which uses [MuSig](https://eprint.iacr.org/2018/068)-style key aggregation applied to one-time addresses.
The approach follows two separate goals: one is to derive all shared key images, each of which is of the form `1/r_k*U` for a globally-fixed group element `U`.
A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified for this purpose, requiring a many-to-many share derivation described elsewhere.
The second goal is simply to compute a quantity that is linear in each shared secret key `r_k`; by assuming only honest-but-curious players, this is straightforward and only requires communication with a designated player, here called the dealer, who is unable to learn any other players' secret shares.

Note that verification of a Triptych MPC transaction necessarily proceeds identically to a standard transaction.


## Proof

To proceed with the Triptych proof, each player `i` selects a random set of scalars `{rho_ij^(k)}` for `j = 0..m-1`, computes `{rho_ij^(k)*G}` and `{rho_ij^(k)*J_k}`, and sends the latter two sets of group elements to the dealer.
For all `j`, the dealer computes each `rho_j^(k)*G := rho_1j^(k)*G + ... + rho_nj^(k)*G` and `rho_j^(k)*J := rho_1j^(k)*J_k + ... + rho_nj^(k)*J_k`, and uses these values to compute each `X_j` and `Y_j` in the proof.
The dealer computes the Fiat-Shamir transcript challenge `x` and sends it to all players.
Each player `i` then computes each `z_i^(k) := (r_i)_k*x^m - rho_i0^(k)*x^0 - ... - rho_i(m-1)^(k)*x^(m-1)` and sends it to the dealer.
The dealer finishes the proof, setting each `z_R^(k) := z_1^(k) + ... + z_n^(k)`.
