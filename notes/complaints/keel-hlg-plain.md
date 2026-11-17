# keel-hlg-plain
- The issue's diagnosis was half right: the record was already named (the snapshot author's chain to p names it); what was missing was the carrier rule, and then a receiver that never learned the loose record (nothing awaited it, and its own smaller record blob won over the sender's). Probing `cert_carriers` and `cert_blobs_missing` with eprintln found both in minutes; reading the facade notes first did not.
- `tools/mutate.py` wraps each OLD as an expression when several are given: `|| x` style sites fail to build. Pick whole expressions.
