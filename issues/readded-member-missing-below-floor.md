# A member re-added without history counts a part below its floor missing forever
> Summary: `sealed_below_floor` needs no read secret of A below the rotation's n; a re-added member holds the epochs its removal's rotation listed, so a rotation between its removal and its re-add keeps its non-role parts counting missing at it, though they lie under an epoch it lacks.
> Priority: low
> Tags: sync, engine

Same symptom as the from-now grantee case spec/sync-judgement.md §1 handles: `read_facts(S, c).missing` stays true at quiet, nothing is fetched and the body is never logged there, so no loop and no loss. A sharper test would ask whether the node holds the epoch the rotation's sections lie under (one of those it supersedes, the newest the rotator held), but the node knows the history-box half of that set only when it holds the rotation's own epoch. Fix if a status or harness check trips on it.
