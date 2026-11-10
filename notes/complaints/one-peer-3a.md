# one-peer-3a
- "Networking tier 2" in the task brief: notes/build.md and notes/coordination.md never use the term; the command is in notes/testing.md (By hand, Networking). A grep for "tier 2" finds only complaints.
- `is_request_kind` lacked 34 (Resume): harmless while the session answered Resume itself, it silently dropped a Resume handed to the hub as a node kind. Only a test through the hub caught it; the proto unit test did not.
- Review: moving a store call up to node sync turned its `?` into a failed node step (rest of the step and the input's later outputs dropped, the request unanswered); the session had answered a store error Error 1. Check every `?` moved out of a `LabelStore` method.
