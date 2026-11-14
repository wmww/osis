# A removed node signs rotations as a key actor it made
> Summary: A removed node keeps its old epochs' inner key, so it can seal a rotation's inner signature as any key actor it creates. The account's nodes read that fresh tid as the minter: no removal hits it, so the removed node's fork counts there as a head, its writes count, nothing rejects it (outsiders that took it first are never warned), and every node of the account rotates on every pass. Needs a rule for who is a node that the removed node cannot forge.
> Priority: critical
> Tags: security, perm, engine

## Repro
`cargo test -p osis-engine --lib a_removed_nodes_fork_signed_as_another_key_actor_counts_nowhere_spec_permissions_5_4 -- --ignored` (core/engine/src/rotation/tests_signing.rs). Node 0 removes X. X forks from the closed epoch and writes there, with each inner signature re-sealed as another key actor Z. At nodes 0 and 1 the fork is a head and X's write counts. Each signing pass both rotate again: the fork stays a blocked head that no merge names (Z is on no roster) and that `unanswered` never rejects (it is not disregarded).

## Cause
`Core::inner_signer` accepts any key actor whose record is held. `osis_perm::Devices::minter` is then taken as identity, and a removal hits only rotations minted by the removed tid (`Chain::stands`). Main has the same `inner_signer`. Forks stood there anyway, so this branch's first-seen rule does not add the hole, but it does rely on minter identity.

## What cannot fix it
Everything X can sign at an epoch it holds can be forged: grants to Z on D, a self-grant at the first epoch (if X held it), even D's rotations, since X signs as P. So "Z has a grant on D" or "Z is boxed in D" is not proof. The roster judged by the epoch rule would be proof, but the chain is an input of that roster (the circularity the side rule avoids).

## Options
1. **First-seen grants (fits Tess's rule).** The account's nodes place D's grants with the rotations. A minter counts as a node for rotation r only through a chain of grants back to the account's creator (the grant in the commit that created D), each grant on r's line. A grant by m is hit by a taken removal of m when it is beside that removal: signed at an epoch not strictly before the removal's epoch, or at that same epoch but held after the removal's rotation. Anything else is hit by every removal (it already is for "opens to no node"). A thief that paired Z before being removed keeps Z until Z is removed too, as when it paired Z in plain sight. Own devices that held X's grant to Z in a different order may disagree, as they may on revocations. The model (`forks`) needs a thief that mints as fresh identities.
2. **Remover's list.** A grant by m at the removal's epoch stands only when the removal's rotation names it in its D thing list (the epoch rule's cutoff). Order-free, but it reads names on D in the chain build, so it is circular as the roster is.
