# Stubs: grants with the granted thing, things found by references
> Summary: The principle behind stubs, grant signals, locators and notices (Tess), where each rule lives in the spec, why the rules have their shape, and the alternatives rejected. Owed work and open questions: notes/stub-rewrite.md.

**Principle (Tess):** a grant is the granted thing's own data, never its holder's. A node syncs what its references reach, and its role on a thing is that thing's grants as it holds them: signal → reference → sync → permissions. Telling a holder is optional; a grant nobody is told of is a valid state and holds the holder nothing. Nothing is kept with a holder, or sent to it, for having been granted something; nobody can make another track, remember or sync what they granted. Signals carry values only. No store learns how many holders or grants a thing has.

## Where the rules are
Each rule is stated once, in the spec; this note restates none. Words: notes/terms.md.
- What a unit carries (stubs, the holders on its chains, carriers), first entry, holding a stub, the sync set, a stub leaving: spec/sync-set.md §2-§3. A stub's cut, the sync-only cut, a hop's removal: spec/permissions.md §4 Stub, A hop's removal, Copies. A stub's holders and stores: spec/sync.md §3; the stub class: spec/sync-opens.md §4 Source.
- References in held history (a fire's included): spec/data-model.md §8 Held history. An account's inbox: spec/sync-inbox.md §1.
- Grant signal: spec/sync-inbox.md §5, its value spec/data-model.md §9, what a forged one can do spec/sync-hostile.md §1. `Osis::grant` sends one unless `GrantOpts::quiet`.
- Locator and redeeming: spec/wire.md §10, spec/sync-set.md §4-§5. Pairing hands over the account's locator: spec/permissions.md §8.
- Notices: spec/permissions.md §4 Notices, taking one spec/sync-inbox.md §2, bytes spec/wire.md §9 and §11.2, the crypto spec/crypto.md §5.
- Entry by role: spec/sync-opens.md §4-§6 (ByRole), a stopped store spec/sync-judgement.md §6 Stops.
- KEM keys a keyset carries: spec/crypto.md §3 Published KEM keys.

## Why the rules have this shape
- **What a sync ID carries is what some node logged** (notes/terms.md, Log). A rule saying a unit carries X's stub describes what a node reading the unit and holding X's role entries logs; with no such node there is no stub, and the reference is a bare one (`NotCarried`).
- **Carrying X whole includes its stub**, so whether U's keys open X is always judged from what U carries of X. That one rule covers public things (the public's open boxes are in every cut) and a unit's own grants.
- **A reference at sync brings a stub** (U's thing holding sync or above on X, its keys not opening X): with "keys open" alone a thing held at sync through a holder is never entered, while the same role granted directly is (held-model `closure::entry`).
- **The holders on a unit's chains are stubs in it; the holders a roster names are not.** A role-class aspect's weaks bring no stub: counted, a unit carrying X would hold the stub of every holder in X's roster its keys open, which is grant-driven entry (held-model control `Chains::Up`; `stubs::a_holder_on_no_chain_is_no_stub_*`). Chain stubs are the one way up from a thing; the roster's holders stay known as backlinks.
- **A chain holder the unit carries whole is no stub**: otherwise a chain of local dependents made independent gave every holder again at each rotation (`scale::a_deep_dependent_made_independent_costs_its_depth_per_rotation`).
- **A held signal's thing is held as a stub by the fire's weak** (held history, the inbox's setting holding its targets) while the signal is followed, before entry too: a stub is a vertex whatever secrets of its thing are held (spec/sync-set.md §2 First entry, Holding a stub), so the signal has no retention root or holding rule of its own.
- **Who follows a signal is a node reading its holder**: a node reading another account's inbox but not the account could never open the notice its entry needs (`flows::tests_signals::a_signal_is_followed_where_its_holder_is_read_*`).
- **A KEM key stays where the keyset it supersedes had one**: a rotator judging "the thing holds a role somewhere" needs to learn of every grant to it, which nothing guarantees (KemKeys.tla `KK_untold` fails; `KK_sticky_*` pass).
- **A notice is sealed per connection by a reader, never stored**: a store keeping X unread then holds nothing per holder or grant, and the blob format needs no per-holder key. A holder that cannot open a commit by its wrap gets in only by meeting a reader of X, never a store alone; a holder behind already gets back in only by role (notes/sync-opens.md).
- **A removal on a chain hop reaches the units reading through it by the hop's stub**; where nothing honest carries the hop's target beside R, R's readers take the stolen key's writes as valid until the removal reaches them (held-model `spec_reach::reach_a_chain_stub_carries_a_removal_to_the_units_reading_through_it`). That is the requirement's "removal binds honest nodes that receive them".
- **A notice is judged on what it carries**: a node holding nothing of X takes the commit on the evidence its sender chose, so a removed admin can hand a holder its old grant, valid until the removal reaches it. The same holds for a sealed fire; not a new hole.

## Rejected
- **A grant list kept with the holder** (every grant naming a holder copied under the holder's sync ID, searched down from the account): it needs a judgement of which grants count that only the holder's readers can make, fires kept as proof, and a standing read of every holder reached. Asking the granted thing dissolves it. Gone with it: taken or accepted grants, a path a role commit states for its holders, any rule whose job is to make sure a holder hears of a grant.
- **A per-grant entry box in X's steps** (the signal carrying an entry credential): every store keeping X unread sees each box, so counts sync-only holders, standing signals and stranded requests (Entry.tla `EN_sig_bare` fails `StepsBare`). A stranded reader's box in a later step is also never found (`EN_left_next`).
- **A notice logged per (commit, holder) beside the commit**: a store counts told grants.
- **The blob key sealed to each told holder inside the role commit** (the form Entry.tla checks, `NT_*`): it leaks only the commit's padded size, but needs a blob format change and the sealed keys in the clear before the AEAD, so a holder finds its box by trial over every blob or by a flag that counts told commits. The per-connection notice passes the same properties and leaks nothing.
- **A signal carrying commits or boxes** (the holder's boxes sealed into the fire): it makes delivery a duty of the granter and a second entry path; values plus entry by role are one mechanism with locators and pairing.
- **Delivering the public's grant to each sync holder**: notes/public-and-cards-brief.md.

## Models
held-model `closure::entry` (properties, controls and hand worlds: core/test/held-model/README.md; notes/closure-model.md) is the sync differential's oracle (notes/test-properties.md, Reference-graph differential). TLA `Entry.tla`, `KemKeys.tla` and Depth0's chain-stub removals: core/test/tla/rotation/README.md. Not modelled: bridges, rotation and re-seals in held-model, notices in held-model, the Dependent-entry oracle gap.
