# A burst of shares from an unmet sender mostly stays lost for 90 days
> Summary: an inbox admin keeps at most `INBOX_WAITING` (32) requests per host and deletes the rest, the sender is never told, and it re-sends only after `INBOX_LIFETIME` (90 days): of 300 shares from someone the recipient has not met, 268 were still missing after 20 resyncs, also after the user accepted. Decided: a stated limit (send the card first); accepting one cannot bring the rest back (the sender sees nothing of an acceptance).
> Tags: node, sync

By design as far as it goes (spec/sync.md §5 Clearing an inbox): a stranger may not fill an inbox. The honest case: two people who have not exchanged cards, one shares many things at once. The deposit is answered OK; the recipient's next pass deletes what is past the cap; the sender holds a delivery it thinks is on its way. Accepting one request connects the sender, so later shares arrive, but what was cleared comes only at the re-send.

Tess left it to the coordinators (she may circle back). Kept as a stated limit, also with an acceptance (option 3 below): what an inbox cleared comes back at the sender's re-send, `INBOX_LIFETIME` after sending.

## Why the cheap step is not cheap
Tried: 40 shares while the recipient is away, it clears to 32, accepts one, 4 syncs.
- Unlabeled things (what `invites` makes): the recipient syncs no label of the sender's, so nothing it does reaches the sender.
- Labeled things: the recipient reads the accepted thing's label and holds its deposit seed, yet writes nothing there that the sender applies within 4 syncs (6 new entries at the host, no new commit at the sender).
- So "re-send once the recipient acts" has nothing to see. `acted` counts only the holder's writes on a thing the delivery names or one it owns (`cleared_share_sent_again_after_the_holder_acted_elsewhere_spec_sync_3`), so cleared shares come back at the 90-day re-send.

**Decided: option 3, the stated limit.** Options recorded, each a design change:
1. Labeled shares only: accepting a request places a heartbeat under the labels it reached at once; a sender records per delivery whether the holder had shown itself (a holder-side commit under a label the sender syncs that the holder does not own) when first sent, and re-sends one sent unmet once when the holder shows itself. Costs a field per delivery and a scan while one waits; unlabeled shares unchanged.
2. Any share: the payload names the sender's inbox (label, hosts, deposit seed, KEM key), and an accepting recipient deposits a re-send request there. A wire change (spec/wire.md §9) and a new blob the sender acts on; gives a stranger the sender's deposit seed, as a contact card would.
3. Keep the limit: send the card first.
