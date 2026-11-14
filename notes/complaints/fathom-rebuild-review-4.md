# fathom-rebuild-review-4
- The brief named an unpushed sha (a07b707f8): nothing to fetch until the branch merged it under new shas mid-review. Briefs for review of another box's work should name pushed shas.
- Wake mutants survived the existing tests twice (a demotion scope's read-here filter, `joined_link_ended`'s clock read): a sync-level "by time alone" test passes without the wake when the other node keeps talking; cut the node off before the `until` to isolate the clock.
