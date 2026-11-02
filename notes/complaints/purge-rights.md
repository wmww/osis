# purge-rights
- Tier-2 `order::new_device_alike_large` already fails on main (issues/new-device-large-fails.md); cost a detour to prove it was not this branch.
- A purge commit whose reset writes the same value as now has no delta and fails `Misuse`: a test helper reusing one value hit it on the second purge.
