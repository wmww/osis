# held-ambig
> Summary: Workflow snags met while resolving the held-model ambiguities.

- spec_map.py anchors rules by exact sentence fragments (tools/spec_map.py RULES): rewording a MUST sentence fails `--gaps` as a stale rule plus an unanchored MUST; keep the anchored words when rewording.
