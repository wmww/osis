# net-reconnect-design
> Summary: Mishaps on the TLC design round.

- run.sh's `tail` pipeline hides results when a `timeout` kills it; send output to a file.
- run.sh's metadir follows `TMPDIR`: set it to a disk dir or a run fills tmpfs.
- A state field added late (`tested`, `ran`) multiplies the model by 10-100; bound drop cfgs with a CONSTRAINT rather than letting a run reach 100M states.
