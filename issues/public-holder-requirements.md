# The public as a holder: requirements wording
> Summary: The spec makes a thing public by granting read to "the public", a holder that is no thing; spec/requirements.md says roles are held by things only and says nothing of public things. Tess: bless the wording, or have the public be a thing.
> Priority: normal
> Tags: tess-call, spec, perm

## The question
spec/requirements.md Concepts: "**Role**: ... held by one thing on another. A **holder** is a thing with a role on something." Permissions: "Roles that things hold on things, and nothing else." The spec (spec/permissions.md §1 The public) adds a holder that is no thing: a grant to the public makes a thing readable by every party. Keys holding grants already strain the same lines.

## Options
- **(a) Change the requirements** (taken meanwhile in the spec): roles are held on a thing by a thing, a signing key, or the public; add the concept "a thing may be made public: readable by everyone, carried with whatever references it". Fits notes/principles.md (a concept that is not a thing is its own concept, as a key is).
- **(b) Keep the wording, make the public a thing**: a well-known thing with a constant record, keys and secrets, nobody able to sign as it or grant on it. Costs a thing that cannot be edited or granted on (against "things are all made of the same stuff") and constants every node must carry.

Proposed: (a). Design and the reasons: notes/public-and-cards-brief.md (Decisions).
