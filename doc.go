// Package layertree is the Go implementation of the LayerTree specification
// (spec/layertree.md): a covenant-enforced shared UTXO with constant-size
// exit and eviction.
//
// Packages:
//
//   - tree:   leaves, merkle-sum nodes, dense and sparse trees, sibling
//     paths, proof compression and the taproot binding of a root to the
//     tree output (spec sections 5 and 6).
//   - script: generators for the transition scripts of every opcode tier
//     (spec sections 4.5 and 8), checked byte for byte against
//     spec/golden.json produced by the Python reference.
//   - txn:    transaction construction, witness assembly, BIP-341 signature
//     hashes and Schnorr signing for transitions (spec sections 7 and 9).
//   - msg:    off-chain messages (compressed proofs, vouchers, join offers)
//     encoded with lnd's TLV library (spec sections 5.5, 7.5 and 9).
//
// The Python tools under tools/ remain the executable reference: they
// include a tapscript simulator that runs the scripts end to end, which Go
// cannot do until the candidate opcodes exist in a Bitcoin script engine.
package layertree
