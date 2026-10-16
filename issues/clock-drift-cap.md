# A wrong clock silently mutes a user
> Summary: Commits more than MAX_DRIFT (1 h) ahead of the receiver's clock are parked, so a device with a clock 90 minutes fast has every write it makes held by everyone for 90 minutes, with no feedback to its user. Needs a UX rule and maybe a smaller or smarter cap.
> Tags: crdt, api

spec/commits.md §4: a commit whose `ts` is more than `MAX_DRIFT` ahead is pending and counted as not received. Intended to keep a wrong clock from harming others' writes (spec/requirements.md, API). For a chat it means a user with a fast clock sees their own messages locally while nobody else does, for up to the cap, and nothing tells them why. Centralized messengers fall back to the server's receive time.

Options: the receiver reports the parking through diagnostics and a peer-visible signal so the sender's client can warn ("your clock is off"); the sender's client checks its clock against servers' transport time at connect and refuses to stamp far ahead; HLC advancing on receipt already pulls a slow clock forward but does nothing for a fast one. Timeline display should use receipt order with the sender's `ts` secondary when they disagree by much.
