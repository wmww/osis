# A bogus compaction snapshot lets a host split a commit
> Summary: atomic apply counts a missing delta as held when any held snapshot stamped later lists it, of any validity, so anyone plus a host hiding a part can show a commit part by part.
> Tags: engine, security

`receipt::listed` (spec/commits.md §4) reads no signer. A snapshot with a frontier or `Absorbed` naming the commit, signed by anyone whose blob a colluding host serves, makes the hidden delta count as held: the commit's other parts show without it. Probed on the required-retention review: a writer demoted to read, its snapshot stamped after the demotion and invalid, a part of another's commit hidden: the other part reads, the hidden one does not, for as long as the host withholds it. On main too. One commit at a time and after seeing it, where a bogus `required.0^` setting would have been standing (that one now needs a possible admin, `Held::ever_admins`).

Not `ever_admins`: a writer's compaction snapshot is honest and must count (its body may be all that is left), so this needs a possible-writer set beside it, and a writer can still do it. notes/node.md records this floor as a decision by Tess on snapshots. Check against the order harnesses, which rely on "whatever the snapshot's validity" for arrival-order independence.
