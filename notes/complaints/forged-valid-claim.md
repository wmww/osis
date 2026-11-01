# forged-valid-claim
- osis-keys tests kept `Rotation::preview` views (placeholder claim ID 0) as the rotator's state; a later rotation's list then named commit 0, masked while "s established" alone settled a chain. Four tests broke on the list-only rule; they now use `common::applied` with the ID other nodes hold the commit by.
- Reviewer's candidate rule ("at least one listed valid claim settled") is unsafe: a forged valid F settled beside an unsettled R_s (its predecessor R_p withheld) passes s. Worth checking candidate rules against withholding one level deeper.
