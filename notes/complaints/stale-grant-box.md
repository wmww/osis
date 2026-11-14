# stale-grant-box
- A new map field in a core struct needs a reader default in schema/core.osis (`= {}`): without it every `keys.0` state written before the field failed to decode, which surfaced only as "lost access" and stalled contact imports across ~40 osis tests. Cost a bisect; the schema test `fixed_lengths_and_unknown_cases_spec_wire_3` names it in one line, run osis-schema first after a schema edit.
- LocalPeer delivers every commit to every peer: an engine test cannot show which labels carry a record (a "blind" peer there holds the actor's boxes anyway). Placement had to be checked in osis World tests, where several existing paths already carried the grant commits.
- A passing test's eprintln is captured: probes need `--nocapture`.
