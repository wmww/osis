# Ownerless things
> Summary: Owner wants a general, checkable "no owner" thing: a creation record with no owner and no key, so no node can ever act through the owner chain. Replaces the burned-key owner of the chat designs (a kept key is a hidden un-removable admin). Costs, the same as burning a key: no roster snapshots (the role history is never compacted), no recovery when every admin is gone. Non-urgent.
> Tags: permissions, spec, engine

Owner decision: build it as a general feature, not chat-only, and keep owned things the default.

Shape:
- spec/wire.md §3 creation record: a third form, neither owner nor key. The tid commits to it, so every node sees the thing has no owner chain.
- spec/permissions.md §1: an owner chain may end at an ownerless thing. Its admins are edges only, all equal, and may remove each other. Nothing holds owner-chain authority on it or on what it owns.
- A roster snapshot needs owner-chain authority (§6), so an ownerless thing never has one. Its `roles.0`/`tenures.0` grow with member churn (not content); record that in notes/growth.md.
- Derived secrets (§2: a plain thing's secrets derive from its owner) do not exist: an ownerless thing gets random secrets at creation, boxed to its first admin, who is granted in the creation commit.
- Things it owns: owner-chain authority on them ends at nothing, so only edges count there too.
- Moving between owners stays a copy (notes/permissions.md "Moving a thing"): an ownerless thing cannot be transferred, which is consistent.
- Recovery: with no admin left the thing is stuck (members keep reading and writing as granted). The lockout recovery (spec/permissions.md §3) needs an admin, so it applies while one is left.

Open: whether `MAX_OWNER_DEPTH` and the chain certificate rules need wording for a chain ending at a non-key thing.
