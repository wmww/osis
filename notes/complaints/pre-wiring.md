# pre-wiring
> Summary: workflow notes from the Opens 21-23 job (key actors' rosters, links redeemed twice, detached things).

- The roles-model gate at the gate's size costs about 1,150 CPU-s per rule set; weighing four readings of Open 23 against `fixed` took five of them plus a by-hand reading differential. The gate's summary counts can match while readings differ (honest writing follows the rules), so a variant meant to change nothing needs the reading differential (`views_differing`), not just equal failing counts.
- The walk-reach branch landed mid-task, so an Open meant to be "owed in the walk" had to be mirrored there after all: check `git log origin/main -- core/perm/src/paths` again before deciding where a rule goes.
- An engine test's "team" as a thing needs its readers granted read on it before they hold content written on it (an addendum on the team): a key actor's content reached them without that, which hid the dependency.
