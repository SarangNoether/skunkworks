# Omniring analysis

This analysis examines size and verification time estimates for the Omniring protocol. This protocol was developed by Russell W.F. Lai et al. and described in a [preprint](https://eprint.iacr.org/2019/580).

Important assumptions and notes:
- only group operations are considered for timing purposes
- separate transactions are assumed to have no anonymity set overlap
- all operation timing is taken from Monero performance tests on a 2.1 GHz Opteron processor
- anonymity set representation is not included in size computations
- in one protocol version, the key image format is different from the current Monero protocol, requiring a separation of outputs

Note that while current Monero keys consist of two curve point representations, Omniring keys consist of three curve point representations. The spend proving system, however, uses only derived one-time keys (and their corresponding commitments).


## Spend transaction

A spend transaction consumes outputs and generates new outputs. Such a transaction reveals neither which outputs are consumed nor the value of the outputs. Similarly to Monero transactions, the anonymity set for spends must be specified, though multiple spends within the transaction share an anonymity set for improved efficiency.

Spend transactions contain a single Bulletproof-style proof that demonstrates knowledge of a set of private keys corresponding to a subset of anonymity set public keys, shows the transaction amounts balance, and proves that key images are generated correctly. For each output, commitment data and an ephemeral key are encrypted to the recipient using a tagged public-key construction (ECIES is used for these estimates).

To examine the size of a spend transaction, assume that `M` inputs are spent with an anonymity set of size `N`, and that `T` outputs are generated. Note that in most typical transactions, `M = T = 2`. All sizes are listed in scalar/group elements, each of which is a 32-byte representation. Let `m = 3 + N + NM + 64T + 3M` for notational convenience.

Component | Size
--------- | ----
Spend proof | `2lg(m) + 9`
Input key images | `M`
Output commitments | `T`
Output public keys | `T`
Output encrypted amounts | `3T`
Output encrypted masks | `3T`
Output encrypted ephemeral keys | `3T`
Fee | `O(1)`
**Total** | `2lg(m) + M + 11T + 9 + O(1)`

For `N = 128` and `M = T = 2`, a spend transaction is 1.70 kB.

For `N = 1024` and `M = T = 2`, a spend transaction is 1.82 kB.

Unlike some other transaction protocols, Omniring proofs cannot be efficiently verified in batches since almost all generators are unique per proof. Verification of a spend proof is equivalent to a multiexponentiation operation of `2m + 2N + 2lg(m) + T + 9` terms.

We illustrate the practical time complexity for several representative parameters, and give the corresponding timing estimates from Monero performance test code. Here `k(i)` is the verification time for an `i`-multiexponentiation operation.

`N` | `M` | `T` | Time complexity | Time (ms)
--- | --- | --- | --------------- | ---------
128 |   2 |   2 | `k(1329)` | 67.2
128 |  16 |   2 | `k(5001)` | 206
128 |   2 |  16 | `k(3137)` | 137
1024 |  2 |   2 | `k(8501)` | 334
