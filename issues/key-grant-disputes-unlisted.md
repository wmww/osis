# Disputes over a key's grant are not listed
> Summary: `osis` `Dispute::of` drops an admin dispute whose holder is a key (a `signers.0` edge, osis_base `Holder::Key`): the API names holders as things only, so such a dispute shows nowhere and its side cannot be chosen. Its engine side is built (`Engine::disputes`, `choose` take any `Holder`).
> Priority: low
> Tags: osis

- Reach: no product path writes a key's grant but a thing's own record key (`Engine::grant_key` has only test callers; link keys are things minted with a key), so only a hand-written or hostile `signers.0` removal makes one.
- Fix: a holder type in the API naming a key beside a thing (notes/api-design.md), used by `Dispute::Removal` and `Osis::choose_side`. Dropping key holders but record keys is no option: spec/requirements.md has roles held by signing keys (Tess).
