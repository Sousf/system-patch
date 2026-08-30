# Record with: vhs demo.tape
# Needs vhs and ttyd (paru -S vhs ttyd), plus ffmpeg.
#
# Warm the cache before recording, or `a` spends forty seconds and a token
# budget on camera:
#   system-patch analyse libheif >/dev/null
#
# Then trim to whatever is actually pending on the machine. The row indices
# below assume libheif sits three down from the system row.

Output demo.gif

Require system-patch

Set Shell zsh
Set FontSize 15
Set Width 1300
Set Height 740
Set Padding 24
Set Framerate 24
Set TypingSpeed 60ms
Set Theme "Catppuccin Mocha"

Type "system-patch"
Sleep 600ms
Enter

# The scan: every package manager on the machine, plus the CVE lookup.
Sleep 6s

# Walk the flagged rows. The right pane redraws per row.
Down@700ms 3
Sleep 2s

# Manager tabs.
Right@900ms 2
Sleep 2s
Left@900ms 2
Sleep 1500ms

# Source analysis. Cached, so it lands immediately.
Type "a"
Sleep 5s

# Focus the pane and scroll the evidence under the pinned verdict.
Enter
Sleep 1s
Down@120ms 14
Sleep 3s

Type "q"
Sleep 1s
