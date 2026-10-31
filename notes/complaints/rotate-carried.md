# rotate-carried
> Summary: workflow notes from the rotate-carried task.

- The random cycle test did not hit the issue in 4200 more seeds (200000-204199, old code); a direct shape built from the issue's description reproduced it on the first try. Building the shape by hand was far cheaper than seed hunting.
- Reviewer: the brief's scratch dir did not exist; a gate run redirected into it never started, and the background task still reported exit 0 (`; echo gate=$?` hides it). `mkdir -p` it first.
