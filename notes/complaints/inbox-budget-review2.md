# inbox-budget review 2 complaints
> Summary: Mishaps met in the second review of the inbox deposit budget.

- `plant_inbox` writes straight to the host's store with no push: a test must take the node offline around it, or the node never sees the blob. Cost two test rounds.
