# Study: can a key-rotation requirement go?
> Summary: Read-only study (Tess asked; she may answer much later): key rotation is the costliest area (about 258 commits, 25 open issues, three security reviews, a redesign). Find which requirements force that cost and what giving each up would delete, in the style of notes/convergence-study.md and notes/core-triage.md §2. Output a note and entries in notes/questions-for-tess.md; change no code or spec.
> Tags: keys, engine, security, spec

Why: notes/core-triage.md §2.5 found the area converging to stated residuals, but the machinery behind it (frozen coverage, keyset names, departures inside holder actors at any depth, forks from independent rotators, re-seals, epoch establishment; notes/epoch-establishment-study.md, notes/roster-names.md) is the largest in the system, and its planned review (issues/epoch-establishment-redesign.md) has not happened.

Requirements to examine (spec/requirements.md Permissions, Decentralization, Confidentiality): removal never re-encrypts and the removed holder stops reading new content once a writer or admin writes after it; readers never rotate; nothing trusts a host; rosters nest without a depth limit (and groupings may be cyclic); several admins rotate independently with no coordinator; a removal nobody stamps (timed grant, link expiry) cuts off nothing until a demotion.

For each candidate relaxation (for example: a nesting depth limit for confidentiality; only the remover or only admins rotate; removal inside a nested actor takes effect at that actor's next rotation only; one rotator per actor at a time by convention, forks resolved by a simple rule), say: what machinery and which open issues it deletes, what a user or app loses, what stays hard, and whether it keeps the threat model. Use the TLA rotation models where they help. Recommend at most two, simplest first, as questions for Tess in plain words.

Method: a fresh fable agent, spec/ and the notes above, no code changes; cite the requirement sentences that would change.
