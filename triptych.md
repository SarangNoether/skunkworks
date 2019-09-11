# Triptych analysis

This analysis examines size and verification time estimates for Triptych transactions. Triptych is a placeholder name for the linkable ring signature construction [proposed by RandomRun](https://github.com/monero-project/research-lab/issues/56). Monero Research Lab [proof-of-concept code](https://github.com/SarangNoether/skunkworks/tree/lrs/lrs) is also available, but should not be used in production. Security has not been formally demonstrated for this construction.

Important assumptions and notes:
- only group operations are considered for timing purposes
- each transaction is assumed to have a single anonymity set across all spends
- separate transactions are assumed to have no anonymity set overlap
- all operation timing is taken from Monero performance tests on a 2.1 GHz Opteron processor
- anonymity set representation is not included in size computations


### Spend transaction

Since minting is performed identically to the current Monero protocol, the novel proving system application of Triptych applies only to spend transactions. A spend transaction consumes existing outputs and generates new outputs, ensuring that the input and output values balance without revealing them.

As in the current Monero protocol, outputs consist of a public key derived from the recipient's address and a nonce, and a value commitment. The amount and commitment mask are obfuscated and included on the chain so the recipient can decode them and recover the values.

To authorize the transaction with linkable signer ambiguity, spend transactions contain a modified Groth commitment-to-zero proof for each spent input. This proof demonstrates that for one of the inputs, the signer knows the private key, the key image is constructed properly, and the signer knows how to construct an auxiliary commitment to be used later for demonstrating balance. A single Bulletproof aggregate range proof is generated for all outputs.

To examine the size of a spend transaction, assume that `M` inputs are spent with an anonymity set of size `N = n^m`, and that `T` outputs are generated, where `T` is a power of two and currently restricted to `T <= 16`. Note that in most typical transactions, `M = T = 2`. All sizes are listed in scalar/group elements, each of which is a 32-byte representation.

Component | Size
--------- | ----
Modified Groth proofs | `M[m(n + 2) + 9]`
Key images | `M`
Fee | `O(1)`
Output commitments | `T`
Output public keys | `T`
Output obfuscated values | `T`
Output obfuscated masks | `T`
Transaction public key | `T`
Bulletproof range proof | `2lg(64T) + 10`
**Total** | `M[m(n + 2) + 10] + 5T + 2lg(64T) + 10 + O(1)`

For `N = 128 = 2^7` and `M = T = 2`, a spend transaction is 3.52 kB.

For `N = 1024 = 2^10` and `M = T = 2`, a spend transaction is 4.29 kB.

To examine verification complexity, let `k(i)` be the verification time required for an `i`-multiexponentiation operation. Let `B` be the number of transactions to verify in a batch; that is, set `B = 1` for verification of a single transaction.

Component | Unique generators
--------- | -----------------
Modified Groth proofs | `B[N(M + 2) + M(3m + 1)] + mn + 1`
Bulletproof | `B[T + lg(64T) + 4] + 128T`

Note that we only count generators unique to each component when verifying a `B`-batch of `M`-in-`T`-out transactions.

Because the verifier can form a single weighted multiexponentiation operation across all proofs and transactions, the above table has total batch time complexity `k(X)`, where `X` is the sum of all unique generators listed.

We illustrate the practical time complexity for several representative parameters, and give the corresponding timing estimates from Monero performance test code.

`N` | `M` | `T` | `B` | Time complexity | Time/txn (ms)
--- | --- | --- | --- | --------------- | -------------
128 | 2   | 2   | 1   | `k(840)` | 45.0 ms
128 | 2   | 2   | 128 | `k(73103)` | 23.1 ms
128 | 16  | 2   | 128 | `k(341903)` | 127 ms
128 | 2   | 16  | 128 | `k(77071)` | 24.2 ms
1024 | 2  | 2   | 128 | `k(534165)` | 168 ms