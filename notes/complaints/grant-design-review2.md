# grant-design-review2
> Summary: mishaps reviewing the route rule and `wait_synced`.
- A holder test that "fails at once" may be an invite request, not a missing route: a pass finished and the grant sat unaccepted (`World::run` accepts, `until` before a run sees it first). `holds_invites` makes the wait deterministic; print `knows`/`role_on` before suspecting the wake-ups.
- A temporary `find_unrouted` comparison inside `Engine::unrouted` is a cheap whole-suite cache check: no staleness over all of osis's `it` and 30 `grant_to_group` seeds.
