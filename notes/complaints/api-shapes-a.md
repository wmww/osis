# api-shapes-a
- `place` on a thing with no `make_group` silently lost the member (a one-field `group.0` decodes as none); nothing in docs or tests said so. Found only by stubbing `make_group` out.
- Stubbing a call out to learn who needs it took one tier-1 run each and answered the question better than reading: three runs, three different answers.
- The call-site rewrite (args parsed balanced, in a throwaway script) handled about 800 sites; a regex alone would not have. Its exclusions for `.create(c.me())` were wrong: the compiler caught all of them.
- `issues/api-refactor.md` D9's `changes: Vec<ChangeId>` read better than it used: about 150 `.id` sites and 2 `.also`.
