# Requirements: purge-on-replace byte figure
> Summary: spec/requirements.md states purge on replace costs "about 0.5 MB" per edit at 2000 entries; counted honestly (store rows plus the snapshot body) it is about 0.7 MB (notes/growth.md). Either update the figure, or drop the byte number from the requirements (an implementation number) and keep only the user-level property (the app chooses a cost that grows with the aspect's size per edit).
> Priority: low
> Tags: spec, tess-call
