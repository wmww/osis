# A re-share rewriting a holder actor's box can be refused
> Summary: `reshare` (`Reseal::All`) and a stranded report's asked re-seal (`Reseal::Asked`, where a box differs) rewrite every current box of the holder; a rewrite is a removal judged by Authority (spec/crypto.md §4), so a re-sealer holding its role on A only through holder actor M, re-sharing M without showing M, gets its own commit refused (`Permission`). The trigger's re-seal puts only missing boxes and is not affected.
> Priority: low
> Tags: rotation

Untested. Options: rewrite only boxes Authority allows (show M, or skip M's held boxes and put the missing ones), or refuse up front with a named error. An asked re-seal so refused stays asked and is tried again at each later pass end of the actor (bounded: one per current holder); the stranded holder still gets boxes from any other re-sealer. The refusal path is untested (no cheap shape refuses an asked re-seal while the holder stays current).
