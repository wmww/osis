# keel-keys-tail
> Summary: Mishaps met on the keys tail branch.

- A background command and the `mkdir` of its log directory sent in one parallel batch raced: the command started first and failed at once on the missing directory.
- `git rm` stages for the next commit whatever path is added later, so deletions meant for one commit rode in an earlier one; recommitted after a local reset.
- The sides `matrix.sh` takes the heavy lock for about 35 min at 14 jobs; nothing else heavy (the custody holds) can run meanwhile.
