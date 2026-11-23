# app-tile
> Summary: footguns met fixing the tile's TooLarge test.

- The issue framed three causes (summary, limit, encoding); the real one was a fourth: an earlier read (`aspects`) failed first, with `Invalid` instead of `TooLarge`. A one-off eprintln test of each read found it in a minute; the known_failures regex only showed the assert.
- osis `From<osis_engine::Error>` turns any unmatched engine error into `Invalid`, so a bounded engine read not routed through `Reader::bounded` loses `TooLarge` silently.
