# A refused memory entry holds its label unsettled

> Summary: an ephemeral entry refused for the node's memory cap (`Memory::refused`, or `unfit` for good) stays `Kind::Unknown` and opens under a held secret, so it is in `Work::unopened` and every pass of the label judges no deletion and no chunk repair (`unsettled_sets` puts `None`) until it fits or leaves every host.
> Priority: low
> Tags: node-sync, security

- `unfit`: one member's ephemeral commit larger than the node's cap for the label holds every delete and repair of that label at this node while hosts keep it (in memory, until its expiry or the host's restart).
- A memory commit touches `+` aspects only, so it cannot justify a durable delete or repair; the gate could leave out entries known to be memory entries (`Entry::memory`) that are refused, at least for durable aspects. Check what a refused memory entry may carry first (`refused_there` treats one as a possible carrier).
- Found reviewing relink-order (repair waits on the same gate as deletes).
