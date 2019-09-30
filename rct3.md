# RingCT 3.0 analysis

This analysis examines size and verification time estimates for the RingCT 3.0 (RCT3) transaction protocol. This protocol was developed by Tsz Hon Yuen et al. and described in a [preprint](https://eprint.iacr.org/2019/508).

Important assumptions and notes:
- only group operations are considered for timing purposes
- each transaction is assumed to have a single anonymity set across all spends
- separate transactions are assumed to have no anonymity set overlap
- all operation timing is taken from Monero performance tests on a 2.1 GHz Opteron processor
- anonymity set representation is not included in size computations
- the key image format is different from the current Monero protocol, requiring a separation of outputs


## Spend transaction

A spend transaction consumes outputs and generates new outputs. Such a transaction reveals neither which outputs are consumed nor the value of the outputs. Similarly to Monero transactions, the anonymity set for spends must be specified, though multiple spends within the transaction may share an anonymity set for improved efficiency.

Spend transactions contain a single Bulletproof-style proof for all spends demonstrating knowledge of one of the private keys corresponding to an output in the anonymity set for each spend, transaction balance, and the correctness of the construction of key images used for detecting double spend attempts. Output public keys are generated using Diffie-Hellman exchanges with recipients, and a single Bulletproof aggregate range proof is generated for all outputs.

Note that our notation for size and time estimates differs from that of the paper, in order to match existing notation elsewhere.

To examine the size of a spend transaction, assume that `M` inputs are spent with an anonymity set of size `N`, and that `T` outputs are generated, where `T` is a power of two and currently restricted to `T <= 16`. Note that in most typical transactions, `M = T = 2`. All sizes are listed in scalar/group elements, each of which is a 32-byte representation.

Component | Size
--------- | ----
Spend proof | `2lg(MN) + 2M + 17]`
Input key images | `M`
Bulletproof range proof | `2lg(64T) + 10`
Output commitments | `T`
Output public keys | `T`
Output obfuscated amounts | `T`
Output transaction public keys | `T`
Fee | `O(1)`
**Total** | `2lg(MN) + 2lg(64T) + 3M + 4T + 27 + O(1)`

For `N = 128` and `M = T = 2`, a spend transaction is 2.27 kB.

For `N = 1024` and `M = T = 2`, a spend transaction is 2.46 kB.

To examine verification complexity, let `k(i)` be the verification time required for an `i`-multiexponentiation operation. Let `B` be the number of transactions to verify in a batch; that is, set `B = 1` for verification of a single transaction.

Component | Unique generators
--------- | -----------------
Bulletproof | `B[T + 2lg(64T) + 4] + 128T`
Spend proof | `B[2N + 2lg(MN) + M + T + 9] + (M + 1)N + 5`

Note that we only count generators unique to each batchable component when verifying a `B`-batch of `M`-in-`T`-out transactions.

Because the verifier can form a single weighted multiexponentiation operation across all proofs and transactions, the above table has total batch time complexity `k(X)`, where `X` is the sum of all unique generators listed.

We illustrate the practical time complexity for several representative parameters, and give the corresponding timing estimates from Monero performance test code.

`N` | `M` | `T` | `B` | Time complexity | Time/txn (ms)
--- | --- | --- | --- | --------------- | -------------
128 |   2 |   2 |   1 | `k(950)` | 49.9
128 |   2 |   2 | 128 | `k(39685)` | 12.5
128 |  16 |   2 | 128 | `k(44037)` | 13.7
128 |   2 |  16 | 128 | `k(45829)` | 14.3
1024 |  2 |   2 | 128 | `k(272517)` | 84.7
