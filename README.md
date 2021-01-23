# ORE-to-OPE Construction

Implements the ORE-to-OPE conversion from [this paper, Appendix B](https://eprint.iacr.org/2015/1125.pdf).

## Comparison

This construction provides better security than [vanilla OPE](https://eprint.iacr.org/2012/624.pdf), worse security
than [ORE](https://eprint.iacr.org/2016/612.pdf), but has the advantage of **not needing a custom comparator** for its
ciphertexts. Consequently, the ciphertexts can be strings that are compared using a traditional lexicographic comparator.

There are two caveats to this construction when compared to vanilla OPE and ORE:
- Its ciphertext lengths are longer than both vanilla OPE and ORE.
- This OPE also has a failure rate which is adjustable based on the "expansion factor", which is a parameter that
affects ciphertext length. The higher the expansion factor, the less likely there are to be errors, but
the longer the ciphertexts.

For instance, when encrypting u64s (8 byte plaintexts) with an expansion factor of 3, the ciphertexts are 24 bytes in length.

## Benchmarks

For benchmarks:
```
cargo bench
```

This will run the benchmarks, comparing OPE encryption (with expansion factor = 5) to a sha256 computation,
as well as HKDF-SHA256. **Computing a single encryption currently takes about 20 microseconds**.

## Testing the failure rate

To see the effect of the error rate on a set of random u64s, try:
```
cargo run --release 100000 3
```

This will sample 100000 random u64s, sort them, then run OPE encryption on each one, sorting the
resulting ciphertexts, and then compare the original ordering to the new ordering.
