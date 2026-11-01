# host-audit
- Box at load ~80: a one-crate proto test compile took minutes; kept to `-p osis-proto`/`-p osis-host` runs.
- notes/sync.md lines are single 2-10 KB paragraphs: grep for a section header dumps tens of KB; hard to read a section alone.
- Review: the gate's tier-1 proto test that builds and decodes a full 9 MiB message took 8 s at load 20 in debug; kept one such message per test.
