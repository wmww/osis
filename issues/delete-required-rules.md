# `delete` under several required rules
> Summary: A `delete` of a thing whose aspects or groups fall under different `required^.0` rules (every chat, whose messages and settings differ) cannot be one commit, so it is refused and the app must remove those first. Decide whether that stands, whether a delete may be several commits, or whether resets stop answering to required rules.
> Priority: normal
> Tags: api, engine, spec

Each reset of a delete answers to the thing's required retention (spec/commits.md §5: a delta breaking it is invalid), so a chat's message key and settings need two expiries or a `nobody` beside others, and a thing required to expire clashes with its group's `group.0`. Before the one-commit step this split; now it is `Invalid`, saying what to do (test `delete_under_required_rules_says_what_to_do_spec_commits_6`). An undo of such a thing's creation fails the same way.

Options:
1. Stand: the app removes the rest first, as the error says. A crash leaves it half deleted, which is what a removal is anyway.
2. `delete` is several commits and says so, a third named exception to one commit.
3. A delta of resets alone answers to no required rule (it holds no value): one commit, a rule change in spec/commits.md §5 and the validity judge. A reset under `nobody` junk stays small either way.
