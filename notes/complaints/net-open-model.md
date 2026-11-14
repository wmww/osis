# net-open-model complaints
> Summary: Workflow snags met while extending NetOpen.tla.

- run.sh's instance list is one bash array per module with comments containing `)`: a script that finds the array's end by the first `)` line lands inside a comment. Edit the array by hand.
- TLC traces print only the top-level action name (`HonestNext`), not the disjunct; a small diff-per-state script was needed to read the controls' traces.
