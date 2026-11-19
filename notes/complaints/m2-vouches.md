# m2-vouches
> Summary: workflow notes from the S3 model brief (vouches, what no list keeps, addenda gaps in roles-model).

- `tools/heavy` waits for the box-wide lock while another branch's gate holds it: two roles-model runs of under a minute each waited 6-8 minutes. A 15 s search costs mostly queueing; batching every mode into one `tools/heavy sh -c '...'` hold helped.
- A `head` after a search inside `sh -c` closes the pipe and the next printing search panics ("failed printing to stdout"); the summary line comes first, so only the examples are lost.
- roles-model's `Shrink` for addenda worlds drops items, honest addenda with them, so a shrunk "not reached" world is trivially failing; the gaps search prints unshrunk.
