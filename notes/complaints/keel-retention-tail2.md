# keel-retention-tail2
- A derived index computed at open must not decode headers (`check_index`: "headers decoded"), so `Core::destroyed` could not just be re-derived in the fast open: it needed persisted rows. Worth a line in the index notes.
- A memo whose life is a key's stamp (`ix.pending.get(id)`) read before that key is inserted (pending_drops runs before pend) recomputes at the first look: cost tests must look once first. Took a temporary print in memo `kept` to find which container moved; a debug "what moved" hook would help.
