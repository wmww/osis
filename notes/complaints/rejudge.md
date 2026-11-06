# rejudge (fathom-rejudge)
- The "validity changed outside the re-judged set" debug panic names only the commit; finding which input moved took three probe builds (each about 2 min at load 25-40). The message now names the flipped parts; a cause search still needs a hand probe of `part_valid`'s inputs before and after.
- The order harness runs several engines in one thread, so a thread-local "last seen" probe mixes nodes; key probes by something per engine or print per transaction.
- A release build of osis-node `it` took about 12 min at load 40-45 (the scale measurement); two of them dominated this task's wall time.
