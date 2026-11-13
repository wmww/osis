# layout-space
- guibox tiles the window to the output; resizing it across a threshold needs `swaymsg '[app_id=".*"] floating enable'` then `resize set W H`, and a floating window re-centres on resize, so click coordinates move between shots.
- A headless `Ui` test needs the accessibility tree for labels: `WindowEvent::EnableAccessTree` before each `redraw`, since later redraws send only changes.
- (review) guibox `-s WxH` sets the window to an exact width, simpler than floating and resizing for a threshold check.
