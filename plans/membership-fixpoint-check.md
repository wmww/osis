# Check the membership fixpoint
> Summary: Brute-force small membership histories against the layer-1 validity rule (notes/permissions.md) to confirm it terminates with a unique answer and gives the intended outcomes; on a counterexample, propose a stricter rule to the owner.
> Tags: permissions, tests

## Why
Layer 1 of the validity definition is circular: whether an admin's grant or revoke counts depends on whether that admin was revoked, which depends on which other writes count; witnessing adds a second loop (a witness's receipt counts only if the witness stays authorized). The rule iterates from "nobody revoked" until stable. Unproven: that it always stops, and that it has one stable answer regardless of evaluation order. Two stable answers would break convergence.

## Model
A small standalone program (Rust, throwaway, under `tools/` or a test module), independent of the real implementation:
- Actors: owner (key actor), 2-4 admins, 1-2 plain members. Each has one node.
- Events: grant/revoke membership writes with HLC timestamps (allow skew), receipts (which node received which write, at what local time), offline periods implied by missing receipts. Attestations derived from receipts.
- Evaluation: layer 1 exactly as written, plus layer 2 attestation validity as least fixpoint.

## Search
Enumerate all histories up to a bound (e.g. 4 admins, 6 membership writes, small timestamp range, all receipt subsets), plus random sampling beyond it. For each:
1. Terminates (bound iterations; report any cycle of states).
2. Unique: compute all stable assignments by brute force over subsets of "revoked" actors, not just the iteration's result; expect exactly one, and the iteration finds it.
3. Order independence: shuffle input order, same result.
4. Monotone receipt: adding a receipt by an authorized node never invalidates a write (validity only grows with witnesses).
5. Expected outcomes: mutual removal -> earlier timestamp wins; stolen device's backdated mass revoke, received by a member first, is valid, and the owner's further-backdated revoke of that device cancels it; re-grant validates intermediate writes; a cycle of revoked witnesses validates nothing.

## On a counterexample
Minimize it, record it in notes/permissions.md, and propose fixes (e.g. stratify: evaluate revokes strictly in (HLC, node) order with no re-walk; or seed from a different base). Fixes change who wins contested admin conflicts, so the choice goes to the owner.

## Done when
All checks pass at the bound and on a large random sample; notes/permissions.md Open entry replaced by the result; the model's cases become test vectors for the real implementation.
