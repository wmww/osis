# Sync emits no diagnostics: a node that syncs nothing says nothing
> Summary: on the new sync, `serve`, `-v` and `diag --follow` print nothing about connections, dials, failed dials or opens refused; when nothing syncs (a stale address, an unaccepted grant) the operator has `status` alone.
> Priority: normal
> Tags: sync, cli

- The dogfood rehearsal needed strace to find that a node dialed a dead address. At least: a dial failing (address, why), a connection up and down (peer key), an open refused (sync ID, code), a grant held but not accepted.
