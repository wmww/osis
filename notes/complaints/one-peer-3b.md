# one-peer-3b
- A `tee` into a scratchpad subdirectory that did not exist yet ran the whole test command with its output thrown away (tee failed to open, cargo went on): `mkdir -p` the log directory first, or redirect without tee.
