# The paths story reads a user's choice after the fact
> Summary: roles-model `paths`' story checks a node with no order on "its reading after its user chooses the honest lowerings", computed after the history without what the choice would cause (a witness answering once its walk applies the removal), so the promise "after its user chooses, the witness answers and the content shows" is exercised only through B's switch at `AFTER`, and liveness of witness-only content needs a set-aside (~1.8% of checks). Sounder: every no-order node's user chooses at `AFTER` in the generated history; the set-aside goes, the dispute checks run on a snapshot from before the choice.
> Priority: normal
> Tags: tests, perm

Found reviewing d2-trust (89b416576): notes/write-path-design.md §1 First received, "What the honest side is promised, per node"; core/test/roles-model/README.md (Paths). The set-aside is computed from receipts only (sound), and narrowing it is still caught by controls `-no-own` and `-no-receipt`; widening it to all witness content passes the rule, so the set-aside is where a weaker oracle could hide. Do with or before the walk rebuild against the model.
