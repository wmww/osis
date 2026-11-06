# No convention for finding an app AK's schema
> Summary: nothing on the wire names a schema (Tess, round 13), so a generic tool or agent meeting an app AK it has no schema for sees numbered fields; the intended route is by convention through the tid the AK starts with (its maker's), which may carry a note linking the schema's repository, but which aspect holds that note and what it says is not decided.
> Tags: schema, api, spec

The purpose is many apps, generic tools and agents sharing data "like a file format". First-party keys live in the osis repository, so their schemas are found there; an app AK starts with a tid its maker owns (spec/data-model.md §2), and the core distributes no schemas (spec/requirements.md, Versioning).

Open: the convention for the maker tid's note (an aspect, its contents: a repository URL, schema file paths per AK), so a tool can resolve an unknown app key without any core mechanism.

## Proposal (devbox, for Tess's decision; no core mechanism)
- The tid an app AK starts with is an **app actor** the maker owns (one per app or schema family, not the maker's account). The maker makes it publicly readable (notes/permissions.md Public content: a public label, so a stranger holding the tid can fetch its aspects from a node serving it).
- The app actor carries one core aspect, `schema.0: map<string, string>`: AK name (the part after the tid, without the version suffix, e.g. `note`) to a URL of the `.osis` schema file (a repository URL with a path; versions resolve inside the file by the AK's version). An entry `""` names the schema for every AK of the actor not listed.
- Resolution by a generic tool or agent meeting `tid:name.N`: read `schema.0` of thing `tid` (fetching the public label when not held), take the URL for `name` (else `""`), fetch the file, register it; cache by URL. Nothing on the wire changes; the core distributes no schemas (spec/requirements.md Versioning); a maker who never publishes keeps numbered fields for strangers, as today.
- Cost: one core aspect (spec/data-model.md §9), one public label per app actor, served by a node the maker runs or picks, one HTTPS fetch per unknown schema. Rejected: a URL inside `body.0` (not typed, not discoverable); a schema hash on the wire (Tess's round-13 decision against naming schemas on the wire); a registry (a required coordinator).
