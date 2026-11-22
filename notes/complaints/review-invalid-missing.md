# review-invalid-missing
> Summary: workflow notes from reviewing invalid-missing.

- A test's fixture values (the fight's `t:reg.0` already "new") make a `None` assertion on a fresh-looking aspect fail; assert "not the value written" instead.
