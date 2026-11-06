# notes-c
- Three parallel note rewrites: a note one worker deletes while another fixes a link in it conflicts on rebase (modify/delete), and the shared overview index conflicts line by line. Resolve by keeping the deletion and main's index lines, then re-fixing links.
- In a rebase `--ours` is main and `--theirs` the branch's commit: taking `--theirs` on another worker's note drops their edits.
- Code comments cite note sections by heading text; renaming a heading silently breaks them. `git grep "notes/<name>.md <Heading>"` before renaming.
