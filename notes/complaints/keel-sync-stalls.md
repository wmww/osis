# keel-sync-stalls
- Trace lines are cut at 400 chars, so a debug note printing a queue or owed set loses the part that matters; print counts and the first item.
- The 114 stall was set up during `world_of` (+0 ms), long before the script's steps: a trace from `step 0` on shows only its symptom. Read the trace from the start of the connection in question.
- The issue's "seed 48" Register reading came from one trace; replaying the script on the branch (80 of 80 fail) showed no member opens after the revocation at all, so nothing reaches Register. Replay a shrunk script over worlds on the branch before naming the module.
