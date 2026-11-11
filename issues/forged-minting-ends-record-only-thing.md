# A forged expiring minting ends a live thing where only its record is held
> Summary: Anyone holding a thing's record may mint it again (spec/commits.md §5, Limit), with any `expires`. A node holding live thing t's record but no genuine minting (a record learned from a record blob: t a live first admin or holder outside its closure) that receives such a minting (a body or a header-only copy) reads t ended once it expires: t reads absent there, edge writes on t stamped after it are refused, and keys put t's holders in its place, while every node holding t's genuine minting reads t live. A hostile record holder splits honest nodes' authority and keys this way. Not reproduced by a test.
> Priority: normal
> Tags: security, engine, permissions

- Judged from signed data, but the record-only node lacks the genuine minting that outweighs the forged one (`Core::ended` needs every held minting value-less).
- Directions: (a) every certificate set carrying a thing's record carries its held mintings' headers (as the ending's evidence does for ended things), so a record-only node holds the genuine one; costs a header per record per label; (b) an ending needs a minting the thing's record chain authorizes (its creator's), a semantics change for "a minting needs no authority"; (c) the stated limit.
