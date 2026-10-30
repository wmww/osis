# inside-revokes (reviewer)
- Started the per-branch oracles in the background, then edited engine code (and briefly swapped in main's certs.rs to check the new test fails there) while they built: the order and sim runs picked up an unknown mix and had to be rerun. Start oracles only after the last code edit, or run them from a copied binary.
- The engine-level test passed (the revoke is found) while the node-level flow still stranded the label: unit checks of what is placed do not show whether the rotators can act on it; the node test did.
