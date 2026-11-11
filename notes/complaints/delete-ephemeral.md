# delete-ephemeral complaints
> Summary: workflow notes from the delete-ephemeral branch.

- notes/coordination.md and notes/ephemeral.md have very long single lines: a grep or sed of them floods the tool output (58 KB for one section); reading them needs `cut -c` or Read with limits.
- The brief asked for a test that a delete clears ephemeral values "at every node holding them": the design (notes/ephemeral.md Deletion, Limit) drops them at the deleter only, with host entries following; other live holders keep them. Briefs that contradict a stated limit cost a design round to notice.
