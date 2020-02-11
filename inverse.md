# Inversion MPC

A method of [Gennaro and Goldfeder](https://eprint.iacr.org/2019/114) can be modified to collaboratively produce the quantity `1/r*U`, given fixed group element `U` and additive shares of `r`, requiring a many-to-many share derivation that we describe below.
This method is conjectured to be secure against malicious players.

Suppose we have `n` players in the multiparty computation.
Each player `i` holds a secret share `r_i` of the secret key `r`, so that `r_1 + ... + r_n = r`.
Further, each player `i` holds a Paillier secret key, the public key of which has previously been distributed to all other players.

Each player `i` chooses a random scalar `g_i` and sets `G_i := g_i*U`.
Each player `i` chooses a random scalar `m_i`, computes a commitment `Comm(G_i,m_i)`, and sends the commitment to all other players.
Player `i` then computes the quantity `c_i := E_i(x_i)`, where `E_i` represents Paillier encryption using the public key for player `i`, and sends `c_i` to each player `j`.
Player `j` chooses a random scalar `b_ji` for each such receipt.
Player `j` computes `c_j := g_j*E_i(x_i) + E_i(-b_ji)` using Paillier homomorphicity, and sends `c_j` back to player `i`.
Player `i` sets `a_ij := D_i(c_j)`, where `D_i` represents Paillier decryption using the secret key for player `i`.

After all players have completed this exchange, each player `i` holds scalars `a_ij` and `b_ij` for each other player `j`.
Each player `i` computes `d_i := x_i*g_i + Sum[a_ij + b_ij]`, where the sum is taken over all other `j`, and sends `d_i` to all other players.
Each player `i` then sends their commitment openings `G_i` and `m_i` to all other players, who check against the commitments.
Each player `i` also sends a Schnorr proof of knowledge of the discrete logarithm of `G_i` with respect to `U` to all other players, who verify the proof.

Each player computes `d := d_1 + ... + d_n`.
Each player then computes `J := 1/d*(G_1 + ... G_n)`; this is the shared key image `1/r*U`.

Insecure example code demonstrating this computation is [available](https://github.com/SarangNoether/skunkworks/tree/inverse-mpc), but should not be used in production.
