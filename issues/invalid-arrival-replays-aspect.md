# An invalid delta's arrival recomputes its aspect's deaths
> Summary: `join_part`'s `unmerged` marks the aspect whenever a held body has a relative keep bound, so each forged write on such an aspect replays every held body (`replay_all`), though it took nothing. A forged write can itself be that bound.
> Tags: engine, retention, security

Measured in a debug build: 20 us per small held body (2000 bodies: 41 ms per arrival; a release build should be several times less). Bodies a snapshot covers are gone, so this matters on an aspect that does not compact. The forger needs a chain to the thing, not a right on it.

Not the only such cost: a forged write that supersedes (`dots_supersede`) rebuilds the aspect as well (`unmerge_part`), so fixing the mark alone does not make an invalid arrival cheap. A fix for the mark: only when the state held a write under one of the arriving delta's dots before its join (a write of another nested in its creation), else nothing it took can need a date.
