# One malformed synced value fails typed reads
> Summary: A synced aspect may hold a value of another shape (or an enum case from a newer schema revision); `db.get` then returns `Error::Type`, and an app that reads many things with `?` fails a whole screen for one odd thing. The app wraps every read to turn type errors into absent.
> Tags: core-ask, api

Repro: app/src/data.rs `Data::get`.
Ask: decide the API's stance: a lenient typed read (`get_lenient`, or `Option` on mismatch plus a diagnostic), or document that apps must handle `Error::Type` per thing.
