# A contact tile's unreadable emails test fails
> Summary: osis-app `fields::a_tile_tells_of_emails_it_cannot_read` fails on main: a contact's summary over emails past the read limit does not come back as `Error::TooLarge`.
> Priority: normal
> Tags: tests, app

The test sets `read_limit = 1000`, writes 100 emails to a person's `EMAILS` and expects `Cx::summary` to fail with `TooLarge`, so the tile tells of emails it cannot read instead of showing none. It panics at app/tests/it/fields.rs:110:

```
assertion failed: matches!(osis_kit::view::Cx::new(&d, &w, false).summary(c),
    Err(osis::Error::TooLarge { .. }))
```

Fails on main at 03c4b4bc7 (built with `tools/bin-at`). Find whether the summary stopped reading the emails, the read limit stopped applying to it, or the test's value no longer exceeds the limit; fix the one that is wrong.
