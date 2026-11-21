# A3 draft: spec/crypto.md
> Summary: Draft spec text for stage A3 (not in spec, not built): §4 Carried demotions stop being a delivery path of their own: the demotions a held keyset carries are a seed of the sync ID's required set placed by the evidence rule, not "with the keyset". Map: notes/a3-spec/README.md.

Written over spec/crypto.md §4 as A2 leaves it ("chain certificates" read as evidence). Replaces the Carried demotions sub-bullet "Whoever places a keyset under a sync ID ... places with it the `roles.0` deltas of the commits it carries, with their authors' chain certificates". Every other bullet *stands*, the judging rule (Held keyset: held only with the edge writes of every commit it carries) included.

## 4. Key access
- **Carried demotions**, its placing sub-bullet: a demotion a keyset carries is in the required set of each sync ID S under which that keyset is required (Carried, Reported), with its evidence (notes/a2-spec/permissions.md §4 Evidence of a commit), as a certificate copy where S's bodies do not carry it: one copy per (demotion commit, thing), the same copy a body's evidence requires where it does, logged by any node whose view requires it and kept while that keyset is required there. A held keyset of M lacking a carried demotion counts as not arrived (Held keyset), as it stands.
