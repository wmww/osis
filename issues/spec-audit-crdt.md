# Spec audit: crdt encoding and read rules where code and spec part
> Summary: Code-side bugs and open decisions from the spec audit of spec/crdt.md (spec-side wording was fixed on branch spec-audit): link comparison in copy and key order, enum case range, carried writes a prune would drop, fragment nesting cap, set element value stamps, commit-level stamps, misplaced §9 algorithm; no crdt byte vectors.
> Tags: spec, crdt, tests

## Code bugs (spec is right)
- **Links in copy order and entry key order**: spec/crdt.md §3.3 rule 2 and copy order say canonical bytes, links by their bytes. `crdt/src/state.rs` `opt_value_cmp` (reused by `Key`, `fragment.rs`) compares `Value` order first, links by content hash only, bytes only on a tie: two values with equal-hash links order differently from bytewise, and two keys of one dot differing only in link bytes collapse (that delta is rejected). Compare encodings when either side holds a link. The crdt model has no links, so nothing catches this.
- **Enum `case_id` range**: `base/src/cbor.rs` accepts any u64 case; the model and the crdt case write take at most i64. Reject above 2^63 - 1 and say so in spec/data-model.md §5.

## Decisions (code and spec differ, either may move)
- **Carried writes a prune would drop**: `codec.rs` accepts a register `[0,[R],S,v]` with R below S (and composite children or `W` below the same delta's reset), dropping them at join; `Slots` must be prune-stable. Rule 5 reads as forbidding them. Either say "accepted, dropped at join (only `Slots` must be prune-stable)" or reject.
- **Fragment nesting**: the decoder caps fragment nesting at 512 across pages (`codec.rs`, `stream.rs`); the spec has only the per-object CBOR depth and the 64-deep value rule, so a state can read as a value deeper than 64. Put a rule in §3.3 rule 7 (512, or tied to value depth 64).
- **Set/bag element value stamp**: the decoder accepts a value register stamped with a dot other than the element's (`codec.rs` ~425, `remap.rs`); spec says only the creation writes it. Reject in rule 7 or state it.
- **Commit-level writes off the delta stamp**: §2.3 says all share the delta stamp; rule 7 and the code (`seq_wire.rs`, `wire.rs`) reject only `FlagW` off it, other writes are checked against `[lo, hi)` only.

## Misplaced in spec
- §9 calls itself non-normative but gives a full diff algorithm (Myers, pairing): keep the identity rule and `read(join(S, diff)) == v`, move the rest to notes/crdt.md.
- §5.7 clipboard cut/paste (client behaviour) and tombstone byte estimates; justification sentences in §5.7 ("This is why", "Correctness never depends on it"), §6 cycle independence, §8 "so a commit has no size limit", §4.5 "Nothing outside the commit can have observed".

## Tests
- No `crdt/` vector subject: no delta or snapshot bytes for runs, `Slots`, `Commits`/`base`, `Absorbed`, real paging, and no rejection vectors (only `chunker/pages.vec` cutting). CBOR vectors lack link, unknown tag, link map keys, tag depth, large enum case.
- No test cites §2.4, §4.3, §5.3, §5.4; bag float summation, totalOrder and mixed int/float reads are untested.
- tools/spec_map.py reports false "unknown sections" (data-model §4.2.1 from "RFC 8949 §4.2.1", §5.5/§5.6 from crdt-local citations).
