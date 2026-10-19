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
- `padme/` (spec/wire.md §5, hand-written): `l` and `padme` (= padme(l)); `p` and `padded` (= pad(p)); or `padded` with `reject: padding`.
- `tid/key-actor.vec`: as `tid/`, plus `seed` and `signing-key` (from the seed as in `keys/`) and the `nonce` used (random for a node, `kdf("creation nonce", seed, "")` for a link key).
- `kdf/` (spec/crypto.md §1): `purpose`, `secret`, `input`, `out` (the XOF form when longer than 32 bytes); `derive-key-context`, `material`, `out` for a direct BLAKE3 derive_key.
- `keys/` (spec/crypto.md §3, §6, spec/sync.md §2, §10): inputs (seeds, secrets, tid, label ID, step key, index, unix ms) then the derived keys, secrets and hashes, named by what they are. Ed25519 keys are RFC 8032 keys from a 32-byte seed; `-value` fields are canonical bytes of the agility enum value.
- `box/` (spec/crypto.md §1, §4, spec/wire.md §7, §9): the recipient by `recipient-kem-seed`; slot fields (`actor`, `member`, `role`, `n`, `nonce`, or `label-id`, `step-key`, or `recipient`, `prefix`), form fields (`keyset-n`/`keyset-nonce` or `keyset: none`, `suite`; `s-epoch-n`/`s-epoch-nonce`), the `ad`, randomness in draw order (`ephemeral`, the X25519 private key, then `mlkem-m`), `payload` (canonical bytes), then `sealed`, `wrap`, `box` or `blob`. Rejections: `reject: decrypt`.
- `wrap/` (spec/crypto.md §5): `read-secret`, `blob-id`, `blob-key`, `wrap`; a blob over an opaque `prefix` with its `plaintext`, `padded`, `blob-key` (the randomness drawn), `blob`, `blob-id`. Rejections: `reject: decrypt`.
- `token/` (spec/crypto.md §7): `secret`, `salt`, `token`, `token-hash`, `level`, `prefix-salt`, `commitment`.
- `sign/` (spec/crypto.md §2, spec/wire.md §11.2): `domain` (or the open inputs and their `digest`), `seed`, `public`, `digest`, `signature`.
- `schema/` (spec/data-model.md §9, §10): case `core schema` with `id`, `revision`, `value` (canonical bytes of the core schema as a `schema` value: every field written, `none` spelled out, docs included) and `hash` (unkeyed BLAKE3 of `value`); then per core aspect `ak` and `value` (canonical bytes of a typed write through the core schema type: every declared field present).
- `commit/` (spec/wire.md §4, spec/commits.md): inputs `signing-seed`, `dedup` (dedup secret of every touched thing), `token-secrets` (`level:secret` for the admin, author-chain write and thing write secrets), `salt` (the header salt drawn), `delta-<ai>-<di>` (canonical delta or snapshot bytes); outputs `header` (canonical bytes), `commit-id`, `signature` (raw Ed25519 under `"osis v1 commit"`), `blob` (commit blob plaintext, unpadded). A header-only purge rewrite gives `blob` and `commit-id`. Rejections: `header` with `reject: <rule>`: `parked-version` (format version above ours: park, spec/versioning.md §2), `aspect-class`, `membership-expires`, `expires-ts`, `purge-expires`, `counter-range`, `order`.
- Further subjects (blob, step, inbox, signal, link, proto, bundle) are documented here as they land; MANIFEST lists them.

## Manifest and freezing
`MANIFEST` lists every file: `provisional` (checked; may change with the implementation), `pending` (named, not yet producible), or `frozen <blake3> <FC-n>`. A frozen file's bytes must hash to the listed BLAKE3; changing one is a format change: add a `## FC-<n>: <title>` entry to `FORMAT_CHANGES.md` naming the file and the reason, then run `gen-vectors freeze <path> FC-<n>` to record the new hash. The runner fails on an unlisted file, a missing listed file, a changed frozen file, or an entry that does not name the file.

## Running (osis)
- `cargo test -p osis-vectors`: one test per file, plus the manifest policy.
- `cargo run -p osis-vectors --bin gen-vectors`: rewrites every provisional generated file from the implementation (frozen and pending files are never touched). `gen-vectors list` shows status and case counts.
- Generated files must equal a fresh generation; hand-written files (`cbor/`, `padme/`) are checked case by case.
