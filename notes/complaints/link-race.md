# link-race
- Sim trace lines are cut at about 200 chars, so step IDs and keys in `Open`/`Step` frames show only their first bytes; telling which step a claim names took prefix matching by hand.
- The host diagnostic "proto: malformed reply to no request" in the failing round was a red herring: the sim's link fault duplicates a frame (`LinkFaults::dup_pct`), so a request is answered twice. Nothing in the trace says a frame was a duplicate.
- The failure looked like "nothing retries a Failed label", but it is retried every `resync_ms`; each retry recomputes the same tries. The roster each node judged (printed from the scenario by hand) was what showed the cause.
- Review: the actors a node "holds" live in three places (`core.accounts`, `ix.secrets`, `core.key_actors`); a probe that widened claims to `ix.secrets` keys left the account out and failed for the wrong reason. `claim_keys_of(None)` is the real "every held actor".
