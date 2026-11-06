# The API once owners go
> Summary: What the public `osis` API leaves for owner removal: three doc-hidden calls, what replaces them for thin clients, a group's holders and chat, and room for dispute calls. Names that wait for the same work: issues/node-host-unify.md, Names left.
> Tags: api, owner

Tess's direction: `create()` takes no owner and `owner_of` goes; `create_owned_by(owner)`, `create_ownerless(admin)`, `owner_of`, the CLI's `ownerless` are doc-hidden and marked until then. These need an answer:
- A thin client: `create()` is `Invalid` (its actor goes with it), so it calls `create_with_admin(g)`: visible, CLI `create --admin G`. Today `g` is its owner. The owner work makes the record name `g` as first admin, and must settle that write on `g` is enough to name it (Tess's condition).
- A group's holders: a thing owned by a group is read by the group's holders with no grant (entitlement, spec/sync.md §3): `create_with_admin(g)` too, which after owners holds through `g`'s role on the thing instead. `add_with_grant` stays for what is already made.
- Tree-of-things: `create_owned_by(x)` in tests, on things that are no actor: goes with owners.
- Chat tells an account from a team and a link key by `owner_of` (`held_through`, `link_key`); the app's `reach` starts from it. `Holder` has no `may_grant` or tie: `grants` one level down covers them.
- Chat's `create_ownerless(me)` becomes plain `create()` plus a durable write: nothing else in it needs an owner.
- `Admit::Own` is "groups this account owns": it needs a new meaning.

Dispute calls (`disputes()`, `on_dispute(f)`, `choose_side(..)`) are built as plain calls on `Osis`, per-node choices, nothing on `Write` (notes/api.md, Sharing and roles).
