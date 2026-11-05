# header-trust review
- Forging a role-class aspect in a test (`label.0`) needs Kind::Role, Form::Commit and the aspect's fixed retention; three build errors to learn that (`forge_on` in tests/it/validity.rs now handles it).
- A "fix disabled" probe that only re-adds the header insert passes live (a later `set_state(None)` on the invalid part removes it again) and fails only after a reload: probes of derived indexes need a reopen.
