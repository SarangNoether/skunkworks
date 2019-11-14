# RingCT 3.0 analysis

This analysis examines size and verification time estimates for the RingCT 3.0 (RCT3) transaction protocol. This protocol was developed by Tsz Hon Yuen et al. and described in a [preprint](https://eprint.iacr.org/2019/508).

Important assumptions and notes:
- only group operations are considered for timing purposes
- each transaction is assumed to have a single anonymity set across all spends
- separate transactions are assumed to have no anonymity set overlap
- all operation timing is taken from Monero performance tests on a 2.1 GHz Opteron processor
- anonymity set representation is not included in size computations
- the key image format is different from the current Monero protocol, requiring a separation of outputs

There are two different transaction protocols that can be built using RCT3. In one (here called RCT-single), separate spend proofs are used per transaction as needed. In the other (here called RCT-multi), a single spend proof is used per transaction; however, in this case the number of spends must be padded to a power of 2. Both versions have an established security model and proofs.

## Spend transaction

A spend transaction consumes outputs and generates new outputs. Such a transaction reveals neither which outputs are consumed nor the value of the outputs. Similarly to Monero transactions, the anonymity set for spends must be specified, though multiple spends within the transaction may share an anonymity set for improved efficiency.

Spend transactions contain one (RCT3-multi) or more (RCT3-single) Bulletproof-style proofs demonstrating knowledge of one of the private keys corresponding to an output in the anonymity set for each spend, as well as correctness of key image construction. Transaction balance is either integrated within the proof (RCT3-multi) or checked separately (RCT3-single). Output public keys are generated using Diffie-Hellman exchanges with recipients, and a single Bulletproof aggregate range proof is generated for all outputs.

Note that our notation for size and time estimates differs from that of the paper, in order to match existing notation elsewhere.

To examine the size of a spend transaction, assume that `M` inputs are spent with an anonymity set of size `N`, and that `T` outputs are generated, where `T` is a power of two and currently restricted to `T <= 16`. Note that in most typical transactions, `M = T = 2`. All sizes are listed in scalar/group elements, each of which is a 32-byte representation.

Component | Size (RCT3-single) | Size (RCT3-multi)
--------- | ------------------ | -----------------
Spend proof(s) | `M(2lg(N) + 18)` | `2lg(NM) + M + 17`
Balance proof | `2` | -
Input offsets | `M` | -
Input key images | `M` | `M`
Bulletproof range proof | `2lg(64T) + 10` | `2lg(64T) + 10`
Output commitments | `T` | `T`
Output public keys | `T` | `T`
Output obfuscated amounts | `T` | `T`
Output transaction public keys | `T` | `T`
Fee | `O(1)` | `O(1)`
**`N = 128`, `M = T = 2`** | 3.26 kB | 2.21 kB
**`N = 512`, `M = T = 2`** | 2.52 kB | 2.34 kB
**`N = 1024', `M = T = 2`** | 3.65 kB | 2.40 kB

To examine verification complexity, let `k(i)` be the verification time required for an `i`-multiexponentiation operation. Let `B` be the number of transactions to verify in a batch; that is, set `B = 1` for verification of a single transaction.

Component | Unique generators
--------- | -----------------
Bulletproof | `B[T + 2lg(64T) + 4] + 128T`
Spend proofs (RCT-single) | `B[2N + 2lg(N) + 11M] + 2N + 5`
Spend proof (RCT3-multi) | `B[2N + 2lg(MN) + M + T + 9] + (M + 1)N + 5`
Balance proof (RCT3-single) | `B[T + M + 2]`

We illustrate the practical time complexity for several representative parameters, and give the corresponding timing estimates from Monero performance test code.

For RCT-single:

`N` | `M` | `T` | `B` | Time complexity | Time/txn (ms)
--- | --- | --- | --- | --------------- | -------------
128 |   2 |   2 | 128 | `k(41221)`      | 13.2
512 |   2 |   2 | 128 | `k(140805)`     | 44.1
1024|   2 |   2 | 128 | `k(273157)`     | 84.8

For RCT-multi:

`N` | `M` | `T` | `B` | Time complexity | Time/txn (ms)
--- | --- | --- | --- | --------------- | -------------
128 |   2 |   2 | 128 | `k(39685)`      | 12.5
512 |   2 |   2 | 128 | `k(139653)`     | 43.4
1024|   2 |   2 | 128 | `k(272517)`     | 84.1
