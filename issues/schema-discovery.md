# No convention for finding an app AK's schema
> Summary: nothing on the wire names a schema (owner, round 13), so a generic tool or agent meeting an app AK it has no schema for sees numbered fields; the intended route is by convention through the tid the AK starts with (its maker's), which may carry a note linking the schema's repository, but which aspect holds that note and what it says is not decided.
> Tags: schema, api, spec

The purpose is many apps, generic tools and agents sharing data "like a file format". First-party keys live in the osis repository, so their schemas are found there; an app AK starts with a tid its maker owns (spec/data-model.md §2), and the core distributes no schemas (spec/requirements.md, Versioning).

Open: the convention for the maker tid's note (an aspect, its contents: a repository URL, schema file paths per AK), so a tool can resolve an unknown app key without any core mechanism.
