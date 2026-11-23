# rotation-fails
- A bisect across two days rebuilt the engine lib tests from cold at each step (5-10 min each, plus lock waits); the issues' suspects list (today's commits) was wrong for every seed: these seeds come from rolling offsets and had failed since the generator reached their shape.
- The property's failing-history log names peers and actors by index but prints tids elsewhere; mapping them by hand was the slowest part of reading each failure.
