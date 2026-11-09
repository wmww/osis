# purge-keep
- Ten osis-node receiver tests sent purge requests without the right through the plain `commit`; once the writer refuses them they need `commit_hostile`. A test that means to be hostile should say so from the start.
- The engine's `Error::Permission` carries no role, so osis maps every engine refusal to `needs: Write`: a purge refused under an admin-only set reads "needs Write" to a writer that has it.
