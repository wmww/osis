# readers-leak
> Summary: workflow notes from the readers-leak branch (blocked walk through readers, TLC).

- Depth0 liveness on a 3-actor, 3-learner instance runs at 30-100 distinct states/min (fairness ENABLED over every learner x actor recomputes Blocked); safety on the same instance is ~1000x faster. `-lncheck final` did not help. Plan liveness on 2 learners or budget hours.
- A 4th learner (second G admin) takes safety from 3k to 700k states.
