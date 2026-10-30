# Ephemeral size limits: residuals
> Summary: Plain ephemeral commits and own covers now split by aspect past inline header lists, and an aspect whose own delta does not fit a blob is held back with further writes refused (notes/ephemeral.md Past inline lists or a blob). Left: presence commits past inline lists, and two gaps in the write-time check.
> Tags: engine, ephemeral

- Presence: one presence commit per actor carries its whole presence state; past inline header lists (over about 1000 presence aspects for one actor) or a blob it is not built (`EphemeralRefused`), so that actor's presence stops syncing. Splitting it would break "a presence commit absorbs every earlier one of its actor"; refusing presence writes past the bound would need a count per actor. Unlikely in practice.
- The refusal check (`check_full`) measures this session's own unexpiring writes of the aspect (all actors), while a cover joins per actor and also carries earlier sessions' held commits: a write can pass the check while the cover still does not fit, so the aspect is flagged again at the next cover and writes keep going in small takes (its held commits grow until caps refuse them). Needs earlier sessions' state past a blob on one aspect.
- Undo/redo of ephemeral batches (`apply_ephemeral` with `reverts`) skips the check.
