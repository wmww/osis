# rereg-churn
- The issue and its test were on `grant-tests`, not yet on main when the task was briefed; the branch was based on `grant-tests` to have them.
- `Net::sent_kinds` counts at send, so it includes what an earlier call queued (a grant's own uploads count before `net.run()`); clear it before the action measured.
- A same-stamp repeat check (`Net::uploaded`) finds re-sends without a change in one assertion; refusals for rate or cap retry legitimately with the same stamp, so it fits only runs without those.
- Review: `Net` never reports `Taken`, so hosts there never hold pushes; host behaviour that depends on held pushes (a code 9 answered before the new head) cannot be seen in node tests.
