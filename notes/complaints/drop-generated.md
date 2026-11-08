# drop-generated
- `tools/spec_map.py --uncited` fails on tests that inherited their citation from a file header once the header changes: moving tests out of a file can leave the rest uncited. Run it right after moving tests.
- `git rm` of the last file in a directory removes the directory too: a following heredoc write into it fails (recreate with `mkdir -p`).
