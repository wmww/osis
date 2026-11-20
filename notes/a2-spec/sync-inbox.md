# A2 draft: spec/sync-inbox.md
> Summary: Draft spec text for stage A2 (not in spec, not built): spec/sync-inbox.md §4 Promotion: a deposit promoted once its evidence is under the sync ID and a complete pass begun after its inputs last moved has ended; the promoter logs the evidence it lacks; no `keys.0` rule. Map: notes/a2-spec/README.md.

Replaces, in spec/sync-inbox.md §4: the Promotion lead's clause on the chain, its third and fourth sub-bullets. Every other bullet *stands*.

## 4. Promotion and clearing
- **Promotion**, its clause on the chain: a writer that verifies a deposited commit S must hold stamps it in its own store (promotes it) only once the commit's evidence for the parts S must hold (spec/permissions.md §4) is under S and a complete pass of S (spec/sync-status.md §1) begun after the deposit arrived and after what its verdict reads last moved has ended (notes/a2-spec/commits.md §4 Provisional), *the rest of the lead stands*.
- A delta S must hold here, valid at the writer: one its bodies carry (on a thing of its sync unit). No certificate copy is promoted: the evidence of a commit promoted goes under S as the promoter's own copies.
- A promoter completes the evidence it holds, logging what S lacks of it as its own certificate copies with the promotion. A certificate copy is never deleted for incomplete evidence.
