# The held writes' rows cost several times the bodies they index
> Summary: a dated aspect past the small bound keeps its held writes in rows (`osis_crdt::Held`, `hx/`): about four rows of 100-170 B per write, and a write rewrites the store page of each position on its path and of its body. A write of one `secrets.0` entry on a 200-holder roster writes 108 KB of store bytes against 22 KB without the rows (`scale::roster_removal_is_linear` fails its flat check across the small bound); a snapshot join reads about 30 rows per write (`scale::snapshot_join_is_flat_spec_permissions_5_2` fails its linear check across the bound). Wants the rows packed into pages by position.
> Priority: normal
> Tags: engine, performance

What a write costs in rows (notes/engine-retention-dating.md Rows, Costs):
- itself (`W`: 16-byte position hash, kind, stamp of up to 58 B; its death and holders), its position's top (`T`) and its step under the position above (`S`), and its body's record of it (`L`): 100-170 B each with the 34-byte aspect prefix. A small body's write is 30-100 B on the wire.
- Store pages: rows are keyed by position hash, so a write, its position's top and steps share a page, but each position above it (tops rise to the root with every in-order write) and its body's rows are other pages, each rewritten whole (4-11 KB).
- Reads: a join reads its position's rows per kind (up to 9 seeks), the floor at each level above, and each top it raises.
- Measured (`scale::text_edits_are_flat`, by hand): an insert in a kept text of 80k / 800k chars writes 68 / 116 KB of store bytes and reads 31 rows; without the rows it wrote 40 / 70 KB and read 23.

Directions, none built:
- Pack the rows into pages under `osis_crdt::Rows` (an adapter: logical keys in path order, pages of a few KB with shared prefixes and a source table per page): a write and the tops above it land in one or two pages, sources and commit IDs are stored once per page. `Held` does not change.
- Without that: sources and bodies as small numbers in values, stamps in keys as `ts` with ties in one row, one scan per position instead of one per kind.
- The small bound (`bounds::SMALL_BODIES`, `SMALL_WRITES`) exists because of this cost (a thing's role aspects would cost several times their bodies): with rows near the bodies' size it can go, and the scale checks stop straddling it.

Red on the branch: `scale::roster_removal_is_linear` (one more `secrets.0` entry: 22 KB at 20 holders, small; 108 KB at 200, rows), `scale::snapshot_join_is_flat_spec_permissions_5_2` (`t:keptset.0` store rows read 11 at n, small; 30461 at 10n, rows).
