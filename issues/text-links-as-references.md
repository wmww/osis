# `osis://` links in text are not references
> Summary: Tess: a tid spelled as `osis://...` in text should count as a reference (a weak one under issues/refs-graph-lifetime.md), so backlinks find a note that links a thing. Today the reference index skips strings and text. To decide: which text is scanned and how (her lean: plain substring matching over Markdown-link parsing, as simpler and better).
> Priority: normal
> Tags: engine, data-model, tess-call

- Today: the index counts tagged tids only; "a tid spelled in a string, text chars" are not counted (notes/engine-refs.md, Counted). A link written in a note body gives no backlink.
- Wanted: every `osis://` followed by a tid's 20 base64url characters (spec/data-model.md §1 text form) in a string or text value of current state is a reference to that tid, from that thing and AK. It keeps and syncs nothing (weak).
- Substring matching against Markdown links only: matching needs no parser, works in every string type and in text an app renders its own way, and a false match costs one backlink row to a thing that may not exist (references may dangle).
- To settle:
  - Text CRDT values (`markdown`, `text`): the index is kept per write at O(the write's reach), so an edit must update matches from the edited span and its neighbourhood (a link is at most 27 characters, so a match can only start within 26 characters before the edit), never by rescanning the value.
  - Large strings are chunked (spec/data-model.md §5); a match may span a chunk boundary. Same question as issues/refs-in-chunked-elements.md.
  - `osis://link/...` (a share link, spec/wire.md §7) is not a tid and must not match as one.
  - Whether the API can tell a text reference from a weak one (backlinks rows carry source and AK only today).
- Independent of the reference graph work: it changes only what the index counts.
