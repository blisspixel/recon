# Linux interface qualification, 2026-10-20

This bounded pass addresses [#238](https://github.com/pueo-labs/recon/issues/238)
and [#239](https://github.com/pueo-labs/recon/issues/239), starting from
`34f565c2`. It uses synthetic `alpha.invalid` observations and local collection
fixtures. No evaluated-target data or external-domain inventory is included.

> **Status, 2026-10-24:** this is a dated record. Issue 240 closed on
> 2026-10-20; the v2.21.2 maintenance batch moved typecheck and release jobs to
> Node 26, which now track each new 26.x release through `check-latest`.

## Environment and corrections

Arch Linux with Omarchy 4.0.6-1, Quickshell 0.3.2.r7.g2b4501a-1, Qt 6.12.0,
Foot 1.28.0, Python 3.15.0 and uv 0.11.17. The session is Wayland at scale 2.
These results establish behavior on this environment, not every desktop or terminal.

The real Quickshell test initially failed because Qt's `Color` type shadowed
the unqualified Omarchy singleton. The production panel and harness now import
`qs.Commons as Commons`; palette and font references are explicit. The Qt input
selection test also reproduced a system-default selection color (`#3584e4`)
instead of the requested accent (`#89b4fa`). Selection now binds to the live
accent and contrasting foreground.

A settled source ladder originally drew another 35 frames during a three-second
idle interval and consumed 0.0757 CPU seconds (about 2.5 percent of one core).
After the correction it draws the final settled state and waits on completion,
without another frame interval. A regression test keeps collection open after
settlement and verifies that neither the frame count nor the sleep count grows.

## Desktop evidence

The native panel was loaded by the running Omarchy shell. Temporary local
instrumentation supplied synthetic lookup, degraded-source, failure and
confidence states; it did not invoke a lookup. Theme changes used the normal
`omarchy theme set` path while the panel remained open, both with the background
transition and with `OMARCHY_THEME_SKIP_BACKGROUND=1`. The host and panel were
not restarted between those theme changes. The original theme and background
were restored, and the temporary instrumentation was removed.

| Theme | Success | Warning | Error | Information |
| --- | --- | --- | --- | --- |
| Tokyo Night | `#9ece6a` | `#e0af68` | `#f7768e` | `#7aa2f7` |
| Catppuccin Latte | `#40a02b` | `#df8e1d` | `#d20f39` | `#1e66f5` |

The focused input retains the host accent. High confidence uses success,
Medium confidence uses information, degraded sources use warning and a failed
lookup uses error. Scene captures from those real windows exclude the rest of
the desktop:

| State | Dark | Light |
| --- | --- | --- |
| Degraded source | [Tokyo Night](assets/interface-qualification-2026-10-20/tokyo-night-warning.png) | [Catppuccin Latte](assets/interface-qualification-2026-10-20/catppuccin-latte-warning.png) |
| Failed lookup | [Tokyo Night](assets/interface-qualification-2026-10-20/tokyo-night-error.png) | [Catppuccin Latte](assets/interface-qualification-2026-10-20/catppuccin-latte-error.png) |
| High confidence | [Tokyo Night](assets/interface-qualification-2026-10-20/tokyo-night-high.png) | [Catppuccin Latte](assets/interface-qualification-2026-10-20/catppuccin-latte-high.png) |
| Medium confidence | [Tokyo Night](assets/interface-qualification-2026-10-20/tokyo-night-medium.png) | [Catppuccin Latte](assets/interface-qualification-2026-10-20/catppuccin-latte-medium.png) |

## Terminal evidence

The compositor frame captures in the [Foot recording](assets/interface-qualification-2026-10-20/source-ladder.mp4)
show the real CLI and ladder with six synthetic collection units, followed by
an intentional three-second wait after all units settle. Only collection is
substituted; CLI routing, progress events, terminal detection, rendering and
stream separation use production code. No flicker or torn frame was observed
in the captured samples. The capture sequence is presented at six frames per second and cannot rule out a shorter
artifact between samples. The raw stderr also has balanced synchronized frames.
Foot supports synchronized output; an emulator without mode 2026 support was
not exercised.

`getrusage(RUSAGE_SELF)` measures process CPU over the post-settlement wait,
including the live renderer task. The measured CPU was below 0.01 percent of
one core. This is one bounded idle sample, not an end-to-end performance SLO.
At the same fixed terminal width, stdout is byte-identical with animated
stderr, discarded stderr, animation disabled and stdout piped. Stdout contains
no escape byte; the animated stderr contains balanced mode 2026 frame markers.

## Regression checks and publication boundary

```bash
TMPDIR=/var/tmp RECON_QUALIFICATION_FIXTURES=/run/user/1000 uv run pytest tests/test_omarchy_panel_runtime.py tests/test_omarchy_integration.py tests/test_omarchy_theme_colors.py tests/test_source_ladder.py -q
uv run python scripts/check.py
```

The focused run passes 62 tests, including real Quickshell execution and Qt
Quick Test. The `/var/tmp` override avoids this machine's exhausted `/tmp`
inodes; it changes no assertions or runtime behavior. The Quickshell test
rejects QML type and reference errors in addition to checking process, palette,
clipboard and cancellation contracts. Missing optional desktop runtimes remain
explicit skips elsewhere. Full-gate and hosted-CI evidence belongs to the
associated pull request. Release status belongs to the dated changelog and
verified release channels.

[#240](https://github.com/pueo-labs/recon/issues/240) remains open: Node 26's
[upstream LTS date](https://github.com/nodejs/Release/blob/main/schedule.json)
is 2026-10-28, after this qualification date. The Node 24 pins remain unchanged.
