# A removed node puts itself back on D through an unaware sibling's epoch
> Summary: A sibling that has not yet received node X's removal rotates and boxes X the new seed (a stated limit). X then signs, as the account, a grant of D to itself at that epoch. At the account's nodes the epoch counts, so the grant counts and X is back on D's roster. The next honest merge then names X's grant and its later writes for good, so X stays a node and gets every later seed. On main and on fork-sides.
> Priority: critical
> Tags: security, perm, engine

## Repro
`cargo test -p osis-engine --lib a_removed_node_readding_itself_is_not_put_back_spec_permissions_5_4 -- --ignored` (core/engine/src/rotation/tests_signing.rs). Fails on main the same way (built with `tools/bin-at --patch`): "peer 0: the removed node is back on D".

## Cause
1. Sibling B has not got the removal and rotates (rb). Its seed is boxed to X (spec/permissions.md §5.5 Limit; spec/crypto.md §4 blocks only encrypting under rb, not counting at it).
2. X signs a grant of D to itself at rb as the account. rb counts at P's nodes, so D's timeline counts the grant: X is back on the roster (`Core::roster_epochs`, `key_holders`).
3. Each node of P merges. `departures` reads X as re-added at rb, so the removal's rotation does not end rb for the cutoff (`signing::ends`). The merge's thing lists then name everything held at rb and at X's fork: X's grant and X's write. Those names are permanent.

`Devices` (fork-sides) skips self-grants, so the chain does not follow X's fork. The roster, departures and cutoff read D's timeline, which does count the grant. Through a forged minter (issues/forged-minter.md) even the chain's filter is bypassed.

## Direction
Principle: what a node of P counts must not depend on commits signed at an epoch whose line lacks a removal the node holds (an epoch the node already treats as blocked for encrypting). Proposal: at a node of P, an epoch blocked there counts as closed for the epoch rule, so a commit at it counts only once named. Honest work survives: B lists its own writes (inner signature, which X cannot forge as B) once it holds the removal; the merge's cutoff names what came before the removal's rotation. This replaces the limit "at P's nodes a write at an epoch an unaware sibling boxed to X counts until the merge" with "counts once its author lists it". Model first: roles-model `forks`/`epochs` need a removed node that writes D edits (self-grant) at a sibling's epoch.
