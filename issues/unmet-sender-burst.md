# A burst of shares from an unmet sender mostly stays lost for 90 days
> Summary: an inbox admin keeps at most `INBOX_WAITING` (32) requests per host and deletes the rest, the sender is never told, and it re-sends only after `INBOX_LIFETIME` (90 days): of 300 shares from someone the recipient has not met, 268 were still missing after 20 resyncs, also after the user accepted.
> Tags: node, sync

By design as far as it goes (spec/sync.md §5 Clearing an inbox, d51, d52): a stranger may not fill an inbox. The honest case: two people who have not exchanged cards, one shares many things at once. The deposit is answered OK; the recipient's next pass deletes what is past the cap; the sender holds a delivery it thinks is on its way. Accepting one request connects the sender, so later shares arrive, but what was cleared comes only at the re-send.

Options, none tried: the sender holds a recipient's deposits at `INBOX_WAITING` while none of them is stamped or answered by a role of the recipient (it cannot read the inbox); or a sender re-sends sooner once the recipient acts on anything of its. Or state it as the limit: send the card first. Owner's call.
