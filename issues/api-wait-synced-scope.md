# `wait_synced` waits for every queued deposit, whatever its scope
> Summary: since node-sync-caps (item 66) a grant to an offline or unregistered recipient keeps its deposit queued until it lands, and `wait_synced(scope)` waits for every queued deposit in any scope, so it fails with `Network` (timeout) for unrelated scopes until that grant lands. Options: scope the deposit wait to the asked scope, or report pending deliveries separately (a distinct outcome/status) so "my data is at the server" can be asked on its own.
> Tags: api, node
