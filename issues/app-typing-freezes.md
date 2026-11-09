# App UI freezes for seconds while typing
> Summary: Tess saw many-second UI freezes while typing in the chat in osis-app (debug build at 90061b685, a store joined to a chat over a LAN serving node). Cause unknown: something blocking the UI thread, or work that blows up.
> Priority: normal
> Tags: app, kit

Seen by hand, not reproduced or measured. No cause known; start by finding what the UI thread waits on during a freeze (a store or engine lock held across sync, a commit on the UI thread, a re-render whose cost grows). Count work rather than timing a debug build.
