# keel-seed6
- `OSIS_SYNC_SHRINK=1` shrinks toward any panic, not the one being studied: seed 6's full history fails one way, its shrink lands on a different failure (the old KNOWN shape). A throwaway loop matching the message was needed.
- `OSIS_QUIET` is not a known test variable (testenv refuses it); quiet goes by another name.
- An engine edit costs a ~5 min rebuild of the osis-sync test binary, so each mutation probe is slow.
