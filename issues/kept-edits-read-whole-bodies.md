# Edits on a kept aspect read held bodies whole
> Summary: on a kept aspect, every write in a new session reads every held body of the aspect whole (the held writes, `bounds::read_held_writes`), a body a write kills chars of is read whole again to date it (`index_date`, O(the part)), and an undo reads the kept body whole several more times. On a text written whole in one commit an insert or move reads 82 KB / 824 KB of blob at 80k / 800k chars, a delete or edit twice that, an undo 410 KB / 4.9 MB (`scale::repro_text_edits_read_whole_bodies`, by hand). Store rows read are flat. spec/requirements.md Scale wants O(change). Fixing it is a redesign of retention dating, not a patch.
> Priority: normal
> Tags: engine, performance

Measured on `scale::text_ops` (a kept text written in one 80k / 800k-char commit, then each op in a new session), spans with debug checks left out:
- Store rows read: flat (4 for a read, 23-31 for a write, at both sizes; `text_edits_are_flat` checks it).
- Store blob bytes read: the first commit's body, a single 82 KB / 824 KB page (one run record: a page cannot split an element), read whole once per insert or move, twice per delete or edit, five to six times per undo.
- `Io` reads (33 / 288 for a delete) are not the measure: they count backend reads including debug-only checks (`index_date`'s `whole_date` joins the dated part, here the whole text, into a copy of the state), so most of that growth is test-only. Count reads by spans (notes/test-scale.md).

Where the reads come from:
1. **Held writes rebuilt per session.** `Core::held_writes_rows` is an in-memory memo: the first write on a dated aspect after open runs `read_held_writes`, which reads every held valid body of the aspect whole (`note_body` → `held_fragment`) and indexes each write by position (`ByWrite`: one entry per text char, so about 800k entries here). Every insert, delete, move, edit and undo pays it once per session. O(the aspect's held bodies) in reads and memory, whatever the change.
2. **Dating a part reads it whole.** A delete or edit kills chars of the first commit, so `date_due` re-dates it: `held_date` reads the part whole and walks every winner (`first_superseding`), documented as O(the part) (notes/engine-retention-dating.md, Costs).
3. **Undo.** `revert` → `undo_writes` reads the kept body whole in `replaced_kept`, `kept_before` (`examine`, `delta_live`, `add`), then items 1 and 2. The decoded-part cache (`Core::decoded`) does not keep the 824 KB part between those reads.

What an O(change) design needs (none built):
- The held-writes index durable and read by position (a paged store table per aspect: position → writes held there with body counts, plus each position's greatest stamp below it for `moved_by`), amended by the bodies that join or leave, so a session reads only the positions a change touches. Run-length entries for a run record's chars, or the table is O(chars) rows.
- A part's date kept incrementally: a join moves a held body's date only through the writes it newly supersedes (the join's `Killed` set, already O(change)) or supersedes earlier; re-dating a part from all its winners is O(the part).
- Bodies readable by position: a run record split across pages, so undo and dating read the pages holding the touched chars, not the whole run.
- Rejected shortcut: max(old date, new deaths) for a join stamped after every held write. It is a second mechanism beside the whole re-date (late joins, leaves), and still needs item 1's per-position lookups.
