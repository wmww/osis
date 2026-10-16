# Replacing a hijacked label
> Summary: The remedy for a removed admin hijacking a label at a server is "a new label under fresh keys", but label IDs derive deterministically from the group's epoch-0 admin secret, so how a second label of one group gets its genesis key is undefined.
> Tags: sync, security

spec/sync.md §2: label ID = hash of the genesis hard-delete key, derived from the group's admin secret; `/label` is a map so several labels per group are allowed. Needed: a derivation for later labels (e.g. from the current admin epoch plus a label index), and when clients switch uploads to the new label and retire the old one.
