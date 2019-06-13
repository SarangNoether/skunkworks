# Lelantus analysis

This analysis examines size and verification time estimates for Lelantus transactions. Lelantus is a transaction protocol developed by Aram Jivanyan for Zcoin and described in a [preprint](https://eprint.iacr.org/2019/373). Monero Research Lab [prototyping code](https://github.com/SarangNoether/skunkworks/tree/lelantus/lelantus) is also available, but should not be used in production.

Important assumptions and notes:
- only group operations are considered for timing purposes
- each transaction is assumed to have a single anonymity set across all spends
- separate transactions are assumed to have no anonymity set overlap
- all operation timing is taken from Monero performance tests on a 2.1 GHz Opteron processor
- a recipient of Lelantus funds must perform a self-spend operation to ensure the sender cannot detect a later spend
- anonymity set representation is not included in size computations


## Transaction types

There are three Lelantus transaction types.
- A [_migration_ transaction](https://github.com/SarangNoether/skunkworks/blob/lelantus/lelantus/migration.md) consumes a Monero output and generates a new Lelantus output.
- A _mint_ transaction generates new Lelantus outputs without consuming any existing outputs.
- A _spend_ transaction consumes Lelantus outputs and generates new Lelantus outputs.

Migration transactions are novel to Monero and are not included in the original paper.


### Migration transaction

A migration transaction consumes a Monero output and generates a new Lelantus output. It does so without revealing which output is consumed or the value of the output.

Like a Monero transaction, a migration transaction includes a CLSAG signature whose input ring includes the true spend, and generates a standard Pedersen commitment as an output. It also includes a new Lelantus commitment of the same value as the true spend, with random mask and a serial number generated from an output public key computed as a Diffie-Hellman exchange with the recipient.

To prove balance, the signer also generates a double-base Schnorr proof of discrete logarithm knowledge for the difference between the Lelantus output commitment and the intermediate commitment offset used in the CLSAG signature. The Schnorr proof is valid only if the commitments have the same value and the prover knows the masks and serial number.

Because the CLSAG signature produces a standard Monero key image, it is not possible to double-spend a Monero output in either a standard transaction or a migration transaction. Note that migration transactions are trivially distinguishable from standard transactions, but that an observer cannot determine which output was migrated (absent other external information).

To examine the size of the transaction, let `N` be the protocol-enforced size of the CLSAG input ring. All sizes are listed in scalar/group elements, each of which is a 32-byte representation.

Component | Code | Size
--------- | ---- | ----
CLSAG signature | `sig` | `N + 3`
Schnorr DL proof | `proof` | `3`
Commitment offset | `C1` | `1`
Output commitment | `D` | `1`
Fee | `f` | `O(1)`
Public key | `Y` | `1`
Encrypted amount | `enc_v` | `2`
Encrypted mask | `enc_r` | `2`
Encrypted private key | `enc_y` | `2`
**Total** | | **`N + 15 + O(1)`**

For the current Monero protocol where `N = 11`, a migration transaction is 832 kB.


### Mint transaction

A mint transaction generates new Lelantus outputs without consuming any existing outputs. It is intended for use in mining operations to bootstrap ongoing supply, according to emission rules. Notably, the amount generated in a mint transaction is public.

The transaction generates an output public key via a Diffie-Hellman exchange with the recipient, and contains a Schnorr proof of double discrete logarithm knowledge; this shows the output commitment is to the correct amount.

Component | Code | Size
--------- | ---- | ----
Public key | `Y` | `1`
Output commitment | `C` | `1`
Amount | `v` | `1`
Schnorr DL proof | `proof` | `3`
Encrypted mask | `enc_r` | `2`
Encrypted private key | `enc_y` | `2`
**Total** | | **`10`**

A mint transaction is 320 kB.


### Spend transaction

A spend transaction consumes Lelantus outputs and generates new Lelantus outputs. Such a transaction reveals neither which outputs are consumed nor the value of the outputs. Similarly to Monero transactions, the anonymity set for spends must be specified, though multiple spends within the transaction may share an anonymity set for improved efficiency.

Spend transactions contain a Groth commitment-to-zero proof for each spent input commitment. Each proof is signed using the spent input's private key. Output public keys are generated via Diffie-Hellman exchanges with recipients, and a single Bulletproof aggregate range proof is generated for all outputs. Balance is shown using a Schnorr proof of double discrete logarithm knowledge.

To examine the size of a spend transaction, assume that `M` inputs are spent with an anonymity set of size `N = n^m`, and that `T` outputs are generated, where `T` is a power of two and currently restricted to `T <= 16`. Note that in most typical transactions, `M = T = 2`.

Component | Code | Size
--------- | ---- | ----
Groth proofs | `spend_proofs` | `M[m(n + 1) + 8]`
Input public keys | `Q` | `M`
Spend signatures | `spend_sigs` | `2M`
Fee | `f` | `O(1)`
Output commitments | `C` | `T`
Encrypted values | `enc_v` | `2T`
Encrypted masks | `enc_r` | `2T`
Encrypted private keys | `enc_y` | `2T`
Bulletproof range proof | `range_proof` | `2lg(64T) + 10`
Schnorr DL proof | `balance_proof` | `3`
**Total** | | **`M[m(n+1) + 11] + 7T + 2lg(64T) + 13 + O(1)`**

For `N = 128 = 2^7` and `M = T = 2`, a spend transaction is 3.36 kB.

For `N = 1024 = 2^10` and `M = T = 2`, a spend transaction is 3.94 kB.

To examine verification complexity, let `k(i)` be the verification time required for an `i`-multiexponentiation operation. Let `B` be the number of transactions to verify in a batch; that is, set `B = 1` for verification of a single transaction.

Component | Unique generators
--------- | -----------------
Groth proof | `mn + BM[N + m + 4] + 1`
Bulletproof | `B[T + 2lg(64T) + 4] + 128T`
Schnorr DL proof | `B(T+1)`

Note that we only count generators unique to each component when verifying a `B`-batch of `M`-in-`T`-out transactions.

Because the verifier can form a single weighted multiexponentiation operation across all proofs and transactions, the above table has total batch time complexity `k(X)`, where `X` is the sum of all unique generators listed. Further, each of the `BM` spend signatures in the batch occupies time complexity `k(2)`.

We illustrate the practical time complexity for several representative parameters, and give the corresponding timing estimates from Monero performance test code.

`N` | `M` | `T` | `B` | Time complexity | Time/txn (ms)
--- | --- | --- | --- | --------------- | -------------
128 | 2   | 2   | 1   | `k(572) + 2k(2)` | 33.6
128 | 2   | 2   | 128 | `k(38799) + 256k(2)` | 12.9
128 | 16  | 2   | 128 | `k(287887) + 2048k(2)` | 95.3
128 | 2   | 16  | 128 | `k(44943) + 256k(2)` | 14.8
1024 | 2  | 2   | 128 | `k(268949) + 256k(2)` | 78.1
