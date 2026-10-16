# Small inconsistencies in notes
> Summary: Fact-checking the explainer surfaced a few claims in notes/ that look wrong or loose.
> Tags: sync, permissions

- sync.md padding: "next step of one eighth of a power of two (Padmé)" caps near 12.5%, while real Padmé caps near 11%. Pick one scheme and fix the numbers.
- sync.md wrap overhead: "~20% on a minimal 200-byte commit" is 48/200 = 24%.
- sync.md / data-model "blind nodes can't see how groups nest": a node holding both a parent and child label sees one blob set inside the other, so overlap partly reveals nesting. State it as part of the accepted overlap leak.
- constraints.md says writes are "verified by every node"; blind nodes can't verify bodies, only label-key signatures. Say "every node that can read".
