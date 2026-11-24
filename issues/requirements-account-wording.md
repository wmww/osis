# Requirements wording for accounts as ordinary things
> Summary: spec/requirements.md still speaks of accounts as core's; with accounts an arrangement of ordinary things (spec/permissions.md §8), one line promises what core no longer keeps. Proposed wording for Tess.
> Priority: low
> Tags: tess-call, permissions

- Release (Data model): "A node that releases everything is left with its own and its account's identity." Core keeps no account: the account is held by a strong from the node root like anything else. Proposed: "A node that releases everything is left with its own identity; an account is kept by its node's references like any thing."
- Concepts, Account: "the identity a person's (or anything else's) nodes act as, and where others reach it" still holds as the library's concept; proposed addition: "an ordinary thing its nodes hold roles on".
- Meanwhile the spec takes the simpler reading: nothing in core refuses releasing an account.
