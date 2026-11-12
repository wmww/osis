# An input method's caret inside a grapheme cluster moves to its start
> Summary: `TextArea` sets an edit's selection through Parley's `select_byte_range`, which moves a caret inside a grapheme cluster to the cluster's start. When an input-method edit leaves the caret there (a combining mark or virama typed before text it joins, a setSelection between a letter and its mark), the caret jumps back, and the next typing lands before the cluster. `ime::Sync` compares with the state before the edit, so when the rounded caret equals the old one the keyboard is not told.
> Priority: low
> Tags: app

Seen by review, not on a device: Gboard's Latin layouts commit whole characters after the caret's cluster. Indic layouts typing a conjunct before existing text, and keyboards sending lone combining marks, would hit it.

Direction: carets at any char boundary in `TextArea` (Parley's `Cursor` is cluster-based, so this is a patch to how the selection is kept, or to the edit model's promise: "the selection afterwards is rounded to clusters", with `Sync` telling the keyboard whenever the selection is not the one the edit asked for).
