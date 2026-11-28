# set_role removing oneself from a thing with one's own link fails midway
> Summary: `set_role(t, me, None)` on a thing `me` administers and made a link to removes `me`'s own grant, then fails `Permission { needs: Admin }` on the second way it holds a role (through the link's actor K, which `me` is admin of as its mint admin), leaving the call half done.
> Priority: low
> Tags: osis

Seen in the CLI (`osis create --admin me ...; osis link make T write; osis set-role T me none --leave-adminless`: exit 4, "needs Admin on ..."). `change_role` treats `me`'s way through K as a link join (`[k] if held_links ...` → `remove_joiner`), but `me` is K's admin, not a joiner; `leave` handles the same case by leaving K as its admin. Either `set_role` on oneself should do what `leave` does, or it should refuse before writing and point at `leave`. Removing oneself this way also leaves K adminless (its only admin is its record edge), which `leave` refuses unless `leave_adminless`.
