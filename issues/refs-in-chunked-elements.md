# References inside chunked set elements and map keys are not seen
> Summary: The reference index skips a link's chunked content, so a tid inside a set element or map key whose encoding exceeds `CHUNK_THRESHOLD` is no reference: backlinks miss it today, and a strong reference there would keep and sync nothing. Fix: every reference in current state counts, whatever the size of the value holding it.
> Priority: normal
> Tags: engine, crdt, data-model

- Where: `Fragment::each_value` walks values the state holds as written; a chunked set element or map key (spec/data-model.md §5: one whose canonical encoding exceeds `CHUNK_THRESHOLD`) is held as a link and its content is not read (notes/engine-refs.md, Counted).
- Only set elements and map keys can hide one: the other chunked kinds (blobs, strings) hold no values.
- Why it matters: with strong references (spec/data-model.md §8 What counts) the rule "a thing is held while a strong reference in current state reaches it" would have a size-dependent exception, and the thing would be dropped silently.
- Needed: the index reads references of a chunked element when it is written or applied (the writer and each reader hold its chunks then, or fetch them), at a cost in proportion to the element, and removes them when the element goes, without reading it again (the rows name their source and AK; whether a count per element is enough to remove them is to check).
- To decide: a reader that holds the link but not yet its chunks. The reference cannot be seen until they arrive; the closure must then follow the arrival as it follows any write.
- Test: a set element just over the threshold holding a reference gives the same backlinks (and, later, the same held set) as one just under it.
