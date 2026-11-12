# theme-sync
- gui-testing: a loop that sources one guibox session's `env` and then calls `guibox start` again inherits that session's WAYLAND_DISPLAY/SWAYSOCK; every later start fails with "compositor did not start" (and wdotool falls back to the real desktop). Start each session from a clean environment (`env -u WAYLAND_DISPLAY -u SWAYSOCK`), sourcing `env` only in a subshell.
