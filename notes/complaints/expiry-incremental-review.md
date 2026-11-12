# expiry-incremental review
- Forging a snapshot copy that wins needs the copy's stamp above the target's: 400 commits from one peer push its HLC counter past another peer's at the same wall ms, so the forged copy silently lost until `lp.advance` came between them. Cost three probe rounds.
- The worker's "known gap" was a reachable visible-read bug that the debug rebuild check catches at once; a ten-line forged-snapshot test would have shown it before review.
