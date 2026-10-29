# Ephemeral session attribution is a writer's claim
> Summary: A carried ephemeral session's writes are judged as the node its `Authors` entry names, and that entry is whatever a commit claims. A writer that names its own session as another (still valid) writer's in its own commits gets an honest compactor to carry its writes under that attribution, so they survive its demotion, which spec/permissions.md §5.2 says they must not. Needs sessions bound to their node. Found by the final review of branch `ephemeral-sync`.
> Tags: security, ephemeral, engine

## Problem
- spec/permissions.md §5.2: a demotion invalidates the demoted node's ephemeral commits and the writes of its sessions that others' commits carry. Carried writes are judged by `Authors` (node, ts) per session; the session ID is a random ID, bound to nothing.
- Attack: writer M writes under session `c_M`, but its commits' `Authors` say `c_M: (H, ts)` for a valid writer H. M's own parts stay valid while M is (the part is judged as M's), and `c_M` is judged as H's. An honest node compacting the aspect attributes `c_M` by `claim_of`, which finds only M's claim (H), so its cover carries `c_M` as H's. After M's demotion its own commits go, the honest cover keeps M's writes as H's for good.
- Limits: M needs write access on the aspect when writing (its own parts are judged as its writes); the writes only outlive its demotion, they gain no rights it did not have.

## Direction
- Bind a session to its node so a claim can be checked: a session ID derived from (node, nonce) is not enough (M names a nonce under H); the session needs its node's signature, e.g. a session record signed once by its node, carried with every snapshot that carries the session's writes, and checked by receivers.
- Until then notes/ephemeral.md (Validity) records the gap.
