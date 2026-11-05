# api-sharing
> Summary: Mishaps from the sharing API step.
- The task said `grant` refuses a lower role on an expired grant. It did not: `Engine::roster` drops ended edges, so `grant` went on to the engine, which accepted it or failed `BadInput` ("a removal without the rotation it requires"). Found only by a probe test.
- A python rewrite script is the only sane way to port 300 test call sites, but its regexes hit `sim.engine(n)?.demote(&..)` too; the `&` argument is what tells engine from API.
- Logging `share`'s `routed` per `#[track_caller]` caller, before removing it, made the sync-then-grant port exact: no guessing which call needed the route.
