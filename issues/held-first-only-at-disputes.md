# Held first is judged only for lowerings that are disputes at the update
> Summary: spec/permissions.md §5.1 Held first records R trusted at the update that brings another party's seed of R, dispute or not; `sides::after_update` judges only the update's disputes, so a lowering that becomes a dispute later (its seed void then, applying after some other change) gets no side where the spec trusts it.
> Priority: low
> Tags: engine, perm

**Rule**: Held first fires when the commits taken in between two readings bring a seed S of held lowering R and the reading before applied R; nothing requires R's trust to change the reading at that update.

**Code**: `sides::after_update` walks `Timeline::disputes()` only and `held_first` needs S in that update's `fresh`. If S is void when it arrives (its author's authority ended by another lowering), R is no dispute then and nothing is recorded; when a later update makes S apply (that other lowering voided, or a user choice), R becomes a dispute with no fresh seed: no side, the walk's.

**World**: admins H, X, Y of g. Y removes X; X's backdated removal S of H (seed of H's held removal R of X) arrives at node N after R, void through Y's removal. Later Y's removal goes void (a fight Y loses at N). N: spec trusts R (H stands); code records nothing (S applies, H removed).

**Fix shape**: judge held first per fresh remote grant-class part over every held frontier-carrying lowering it seeds (the walk's `seeds_alone` inverted), not over the update's disputes; or restate the spec rule at dispute detection if the simpler rule is accepted (disputes take the simplest rule to build).
