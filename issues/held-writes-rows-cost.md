# The held writes' rows cost several times the bodies they index
> Summary: a dated aspect past the small bound keeps its held writes as rows packed into pages (`osis_crdt::Held` over `PagedRows`, `hx/`): about 400 B of rows per write, and a write rewrites five store leaves. One more `secrets.0` entry on a 200-holder roster writes 87 KB of store bytes against 22 KB at 20 holders, a small aspect (`scale::roster_removal_is_linear` fails its flat check across the small bound). Without the small bound a thing costs 58 KB to make against a 15 KB budget whose headroom is 96 B, so the bound cannot go while the budgets stand. Needs a decision: budgets, or held writes that cost nothing until a write dies.
> Priority: normal
> Tags: engine, performance, tess-call

Measured:
- A write is a row for itself, its position's top, its step under the position above and its body's record of it: about 400 B together, keys' shared prefixes left out. A small body's write is 30-100 B on the wire.
- The store rewrites a whole leaf (4-11 KB) for each row or inline page touched. A write's rows lie in five places, keyed by hash: its position, the position below it, each position above it (tops rise to the root with every in-order write) and its body. Packing the rows into pages (`PagedRows`, 3 KB) took the roster write from 108 KB to 87 KB, no further: five pages are five leaves.
- `scale::text_edits_are_flat`: an insert in a kept text of 80k / 800k chars writes 60 / 97 KB of store bytes and reads 52 store rows (68 / 116 KB and 31 with one store row per row; 40 / 70 KB and 23 with the held writes in memory).
- `thing_cost` with the small bound off: an independent thing 57.8 KB of rows (budget 15,000, 14,904 without held-writes rows), a read grant 89 KB at the reader (budget 31,500, 31,368 without). Any row kept for a role aspect at its creation or first rotation passes those budgets.

What would close it, none built:
- Keys in path order inside the pages (a page key cut to the store's key bound, the full first key in the page), so a write, the position below it and the tops above share one or two pages: about three leaves a write. Sources and commit IDs once per page.
- Held writes kept from the first death on an aspect, none before (a join that supersedes nothing writes nothing: the state's winners say so, `retention::Killed`): things and append-only aspects cost nothing, the first death reads the aspect's held bodies once. A text written whole then pays its first replacing edit O(the text), once.
- Or the budgets take the rows' bytes.

Red on the branch: `scale::roster_removal_is_linear`.
