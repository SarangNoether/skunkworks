# Janus mitigation

The [Janus attack](https://web.getmonero.org/2019/10/18/subaddress-janus.html) can be used in an attempt to link known subaddresses, in order to determine if they are derived from the same master wallet address.


## Attack description

A user with wallet view and spend keys `(a,b)` generates a master wallet address `(A,B) := (aG,bG)`. She generates subaddresses `i` and `j` as follows, where `H` is a hash-to-scalar function.

For index `i`:
`B_i := H(a,i)*G + B` and `A_i := a*B_i`

For index `j`:
`B_j := H(a,j)*G + B` and `A_j := a*B_j`

To attempt to link these subaddresses, an adversary generates a Janus output `P`, using transaction private key `r`:
`R := r*B_i`
`P := H(r*A_i)*G + B_j`
Note the mismatched indices in the output public key.

When recovering the output, the recipient computes `P - H(a*R)*G == B_j` and assumes the output is directed to subaddress `j`. If the recipient acknowledges receipt of the transaction, the adversary knows that subaddresses `i` and `j` are linked.

Note that the attack can also attempt to link a subaddress to its corresponding master address.


## Mitigation

To allow the recipient to detect Janus outputs, the sender is required to include a second transaction public key `R' := r*G` using the fixed basepoint `G`.

On detection of the output public key `P`, the recipient computes the detected subaddress spend private key:
`b_j = H(a,j)*G + b`

Finally, the recipient checks that the following equation holds:
`R - b_j*R' == 0`
If the equation holds, the output is not a Janus output. If it fails, the output is malformed and may be a Janus output; the recipient should not acknowledge receipt, but may spend the funds if the output is spendable.


### Correctness

To see why the mitigation detects a Janus output:
`R - b_j*R' == r*B_i - b_j*(r*G) == r*(B_i - B_j) != 0` (for `i != j`)

In order for the adversary to fool the mitigation check, it must provide `R'` such that `b_jR' == b_i*G`, which it cannot do since subaddress private keys are uniformly and independently distributed and unknown to the adversary.


## Considerations

This mitigation requires the addition of a single group element `R' = r*G` for each transaction private key `r` used in a transaction. This point is redundant in the case where no subaddresses appear as recipients, since it has the same construction as a standard-address transaction public key. The presence or absence of additional transaction public keys is already a signal of the presence of subaddress recipients, which is a separate concern.

No additional computational complexity is present when scanning transactions for controlled outputs. For each identified output requiring the mitigation, the complexity of the check is minimal. This check can also be batched across multiple transactions if desired, in order to increase efficiency when computing many checks at once.
