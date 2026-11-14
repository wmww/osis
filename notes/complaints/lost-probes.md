# Complaints: lost-probes
> Summary: footguns met porting the old sync's lost probes to engine facade tests.

- `Engine::own_certificates` has no caller in osis-sync (sync logs certificates through `sync_bodies`/`sync_certificates`); a test asserting on it passes while saying nothing about what sync logs.
- `Engine::promotable` guards a reader's grant and a minted card twice (no closure body, then the author's write): mutating the write check alone fails no test, since nothing reaches it with a closure body by a non-writer.
- spec_map anchors must name a bold rule term; a paraphrase in the parentheses is a "stray anchor".
