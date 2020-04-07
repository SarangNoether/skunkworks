# Arcturus analysis

This analysis examines size and verification time estimates for Arcturus transactions. Arcturus is based on a linkable ring signature construction [proposed by RandomRun](https://github.com/monero-project/research-lab/issues/56) and described in a [preprint](https://eprint.iacr.org/2020/312). Monero Research Lab [proof-of-concept code](https://github.com/SarangNoether/skunkworks/tree/arcturus) is also available, but should not be used in production.

Important assumptions and notes:
- only group operations are considered for timing purposes
- each transaction is assumed to have a single anonymity set across all spends
- separate transactions are assumed to have no anonymity set overlap
- all operation timing is taken from Monero performance tests on a 2.1 GHz Opteron processor
- anonymity set representation is not included in size computations
- the key image format is different from the current Monero protocol, requiring a separation of outputs

In Arcturus transactions, a single spend proof is used per transaction. A comprehensive security model and proofs are in progress.

## Spend transaction

A spend transaction consumes outputs and generates new outputs. Such a transaction reveals neither which outputs are consumed nor the value of the outputs. Similarly to Monero transactions, the anonymity set for spends must be specified, though multiple spends within the transaction may share an anonymity set for improved efficiency.

Spend transactions contain a single Groth-style proof demonstrating knowledge of one of the private keys corresponding to an output in the anonymity set for each spend, as well as correctness of key image construction. Transaction balance is integrated within the proof. Output public keys are generated using Diffie-Hellman exchanges with recipients, and a single Bulletproof aggregate range proof is generated for all outputs.

To examine the size of a spend transaction, assume that `M` inputs are spent with an anonymity set of size `N`, and that `T` outputs are generated, where `T` is a power of two and currently restricted to `T <= 16`. Note that in most typical transactions, `M = T = 2`. All sizes are listed in scalar/group elements, each of which is a 32-byte representation.

Component | Size
--------- | ----
Spend proof(s) | `lg(N)(M + 3) + M + 7`
Input key images | `M`
Bulletproof range proof | `2lg(64T) + 10`
Output commitments | `T`
Output public keys | `T`
Output obfuscated amounts | `T`
Output transaction public keys | `T`
Fee | `O(1)`
**`N = 128`, `M = T = 2`** | 2.50 kB
**`N = 512`, `M = T = 2`** | 2.82 kB
**`N = 1024`, `M = T = 2`** | 2.98 kB

To examine verification complexity, let `k(i)` be the verification time required for an `i`-multiexponentiation operation. Let `B` be the number of transactions to verify in a batch; that is, set `B = 1` for verification of a single transaction.

Component | Unique generators
--------- | -----------------
Bulletproof | `B[T + 2lg(64T) + 4] + 128T`
Spend proof | `(2 + M)lg(N) + 1 + B[2N + 3lg(N) + M + T]`

We illustrate the practical time complexity for several representative parameters, and give the corresponding timing estimates from Monero performance test code.

`N` | `M` | `T` | `B` | Time complexity | Time/txn (ms)
--- | --- | --- | --- | --------------- | -------------
128 |   2 |   2 | 128 | `k(36766)` | 11.5
512 |   2 |   2 | 128 | `k(135846)` | 42.2
1024|   2 |   2 | 128 | `k(267306)` | 82.6
