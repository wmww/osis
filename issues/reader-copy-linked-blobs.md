# A reader's copy goes without its chunk and page blobs
> Summary: A reader relays or deposits only a body's commit blob, never the chunk, tree-node or page blobs it links (`body_sends` adds those for writers only). Where readers hold the only copy (a wiped or new host, an ephemeral body after host and writer restarts, a write-key rotation), a body with a large value or a paged delta does not come back: writers cannot fetch its pages, so they never apply or promote it, and the deposit holds a budget slot.
> Priority: low
> Tags: sync, node

Readers could send the linked blobs with filler wraps as writers do (as deposits when unstamped); they count toward the deposit budget then, so a large body may not fit it. Rare: needs every writer and host to lack the body.
