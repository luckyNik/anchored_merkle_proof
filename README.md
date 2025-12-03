Demonstrative implementation of Anchored Merkle Range Proof protocol proposed in https://eprint.iacr.org/2025/1811.pdf using Rust and Circom. In the early stage of development. 
The author is not an expert in theoretical/applied cryptography (just yet :) ), so this should be treated as an educational project.

CRITICAL: current implementation uses bn254 curve. For Circom compatibility, we should change the curve to Baby Jubjub (known in arkworks as ark_ed_on_bn254).
