# Simplify hand-over forks?
> Summary: Derived identities per fork level, the three-step alias resolution and `/follows` exist only for the hostile-former-owner fork of an operation the requirements call rare. Options to shrink spec/permissions.md §7 for the owner to pick.
> Tags: owner-call, permissions

## Today
A fork (two valid successor records) renames every thing below the forked thing per branch (`hash(K, H_i)`, applied per fork level), commits name resolved identities, every API call resolves aliases, a reader resolves by standing (rights held in a branch), else by its person actor's `/follows`, else dangles, and the backlink index re-resolves on a fork. The derived-tid index costs O(tracked things) per record.

## Options
1. Keep as is (tension 1). Correct and model-checked; the cost is implementation surface and testing.
2. No derived identities: a thing below a forked F keeps its tid and both branches' chains authorize writes on it (content from both merges; secrets fork per branch as epochs do, so each branch stops reading the other's new wraps once it rotates). Forks of F itself still give two identities `hash(F, H_i)`; a reader picks one by `/follows` (default first seen, settable), no standing rule (standing needs per-branch edges, which needs derived identities). Drops the derived-tid index, the per-level renaming, resolution step (1). Loss: automatic branch choice for members with a stake; they switch by hand under attack.
3. Drop hand-over: moving a thing out of its owner's tree is a copy (new tid, history imported as the new owner's snapshot) with an app-level "moved to" pointer on the old thing. Drops §7, `/follows`, alias resolution in the API, and the reason `/handover` records are kept forever (the tenure ledger stays for content and epoch starts). Loss: root key rotation (notes/crypto.md: key actors rotate by hand-over) becomes a full migration of the person actor; the recovery key can then never be changed cheaply.

Recommendation: 2 if forks under a hostile former owner are judged acceptable as a manual recovery; 1 otherwise. 3 only if root-key rotation gets another path.
