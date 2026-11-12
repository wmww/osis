# The compaction trigger's work per write grows with kept history
> Summary: on an aspect whose setting keeps history, the trigger's estimate grows by every applied body (kept ones too) and each weighing reads every held body, so a register or map under keep-for-D reads O(kept bodies) every few writes: 78 bodies weighed over 10 writes at 20 held, 414-618 at 200.
> Priority: normal
> Tags: engine, retention

`retention/compact.rs`: `Trigger::applied` grows an aspect's estimate by each applied body, also one its history keeps (a live body kept while live, a replaced one in history), and `compactions` weighs once the estimate passes `FACTOR` times the last snapshot cost. Weighing (`Load::of`, `candidates`) reads every held body's blob and only then skips the kept ones (`part_keeps`), and the estimate is reset to the countable cost found (0 when all are kept). So on an aspect whose bodies are all kept the trigger weighs every `FACTOR * snapshot / (body + ENTRY_CHARGE)` writes (every two or three for a small register) at O(held bodies) each: quadratic over the aspect's life. Chat writes a keeping setting on its things, so this is its common case.

Measured with the `compact: bodies weighed` cost count (`osis_node::costs::take`), a hosted map under `net.keep(.., DAY)`, 10 writes after n: keys put apart 78 at n = 20, 414 at n = 200; one key overwritten 78 and 618.

Fix direction: count a body for the estimate only when it may count (not kept: `bounds::live_keep`/`part_keep` past), as `leaving::left` already counts one leaving history; a live bound ending at a T alone then needs a weigh at T (a timer, or `Trigger::weigh` from the expiry tick). And filter kept bodies before reading blobs in `candidates`. Then a default test: bodies weighed per write flat at n and 10n kept bodies.
