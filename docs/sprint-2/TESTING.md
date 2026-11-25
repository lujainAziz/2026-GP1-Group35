
## Layout adaptation to text sizes (2026-11-05)

Fixes: the device-details title wraps at name separators instead of mid-word
(invisible break opportunities; visible text unchanged); the settings hardware
card values wrap instead of being clipped with an ellipsis; the device-list
stat labels and the Home stat-card label keep their designed size and
wrap/reflow (the number flows to the next line when needed) instead of being
scaled down; affected cards grow with their content.

Verification: **automated widget tests** (`layout_scaling_transition_test.dart`)
that switch in-place between the smallest (app zoom 1.0 × system 0.85) and
largest (zoom 1.2 × system 1.3) sizes in both directions without rebuilding the
screens — Home, device list, device details and settings — asserting no
overflow during and after each animation and that the full labels remain
rendered at the largest size. Comparison screenshots (small vs large) are in
`evidence/ui/scale-*.png`. These are **not** on-device verification: the
owner's visual review of the running app remains pending.
