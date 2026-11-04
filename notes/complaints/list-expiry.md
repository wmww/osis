# list-expiry
> Summary: Footguns met chasing the expiring list oracle seeds.

- The debug rebuild check prints only the differing lines. To find the cause I had to print the whole kept and rebuilt states, each held part's status, and every `set_state` with a backtrace. A `check_rebuilt` that dumps the held parts on failure would have saved most of the chase.
- After a fix, a seed's shrink can land on a second, unrelated bug (9220029 moved from class 1 to class 2). Reading only "still fails" would wrongly say the fix did not work.
- Review (rv): the 4.7 oracle's class-2 rate varies a lot by offset (1/40 at 9250000, 7/40 at 9260000): one offset says little about it.
