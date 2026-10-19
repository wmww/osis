# osis conformance vectors

Language-neutral test vectors for the osis wire formats (spec/wire.md and the sections it cites). Another implementation passes a file by reproducing every live case.

## Files
`<subject>/<name>.vec`, UTF-8 text. Records are runs of `key: value` lines separated by blank lines; lines starting with `#` are comments. The first record is the header: `subject`, `spec` (the governing section), `source` (`hand-written` or the generator command). Every later record is a case with at least:
- `case`: a name unique in the file;
- `spec`: the spec section it checks;
- `pending: <reason>` (optional): the case is listed but not yet checked; frozen files have none.

Byte strings are lowercase hex. Inputs too large to inline are written as `xof("<ascii>", <n>)` (the first n bytes of the unkeyed BLAKE3 XOF of the ASCII string) or `zeros(<n>)`. Lists of integers are comma-separated without spaces.

## Subjects
- `cbor/` (spec/data-model.md §5): `hex`, then `diag` (the bytes decode, re-encode to themselves, and print as `diag` in RFC 8949 §8 notation: floats in shortest round-trip form with `.0` when integral, `NaN`, `Infinity`; tags as `n(content)`) or `reject: <rule>`. Rules: `truncated`, `too-large`, `too-deep`, `trailing`, `non-shortest`, `indefinite`, `reserved-info`, `int-range`, `utf8`, `map-order` (unsorted or duplicate keys), `set-order`, `simple` (null, undefined, other simple values, half or single floats), `nan` (NaN other than `7ff8000000000000`), `tag-content` (a profile tag around content of the wrong shape).
- `tid/` (spec/wire.md §3): `record` (canonical bytes of the creation record), `tid`, `text`, `uri`; or `record` with `reject: creation-fields` (both or neither of fields 0 and 1).
- `chunker/` (spec/wire.md §6): `table-blake3`, `g0`, `g255` (little-endian bytes of the gear table and entries); `input` with `lengths` (chunk lengths in order).
- Further subjects (kdf, keys, box, wrap, blob, commit, step, inbox, signal, link, schema, proto, bundle) define their fields in the file header comments as they land; MANIFEST lists them.

## Manifest and freezing
`MANIFEST` lists every file: `provisional` (checked; may change with the implementation), `pending` (named, not yet producible), or `frozen <blake3> <FC-n>`. A frozen file's bytes must hash to the listed BLAKE3; changing one is a format change: add a `## FC-<n>: <title>` entry to `FORMAT_CHANGES.md` naming the file and the reason, then run `gen-vectors freeze <path> FC-<n>` to record the new hash. The runner fails on an unlisted file, a missing listed file, a changed frozen file, or an entry that does not name the file.

## Running (osis)
- `cargo test -p osis-vectors`: one test per file, plus the manifest policy.
- `cargo run -p osis-vectors --bin gen-vectors`: rewrites every provisional generated file from the implementation (frozen and pending files are never touched). `gen-vectors list` shows status and case counts.
- Generated files must equal a fresh generation; hand-written files (`cbor/`, `padme/`) are checked case by case.
