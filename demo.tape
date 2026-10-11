# Record with: vhs demo.tape
# Needs vhs and ttyd (paru -S vhs ttyd), plus ffmpeg.
#
# Plays against a staged cache so the take is the same every time and `a`
# replays a stored analysis instead of spending a token budget on camera.
# Point DEMO_CACHE and DEMO_STATE at directories holding system-patch/ with:
#   updates.json   the list to show, Stamp set to the mtime of
#                  /var/lib/pacman/local so it is not rescanned
#   notes-*.json   release notes for every row
#   analysis-google-chrome@<cur>..<new>.json   the answer `a` shows
#   arch-news.json
# Touch every file first; stale entries are ignored. Unset, the tape records
# whatever is pending on the machine, and the row indices below won't line up.

Output demo.gif

Require system-patch

Set Shell bash
Set FontSize 15
Set Width 1300
Set Height 820
Set Padding 24
Set Framerate 20
Set TypingSpeed 60ms
Set Theme "Catppuccin Mocha"

Hide
Type `export PS1='$ ' XDG_CACHE_HOME=$DEMO_CACHE XDG_STATE_HOME=$DEMO_STATE && clear`
Enter
Show

Type "system-patch"
Sleep 600ms
Enter

# The system row: every manager on the machine, and Arch news that needs a
# manual step.
Sleep 3500ms

# Walk down to Chrome. The right pane redraws per row.
Down@300ms 4
Sleep 1500ms

# Release notes for the update, with the CVEs they close.
Enter
Sleep 1200ms
Down@120ms 8
Sleep 1500ms
Escape
Sleep 600ms

# Source analysis. Stored, so it lands immediately.
Type "a"
Sleep 3000ms

# Focus the pane and scroll the evidence under the pinned verdict.
Enter
Sleep 800ms
Down@150ms 16
Sleep 2500ms
Escape
Sleep 600ms

# The other flagged row.
Down@300ms 2
Sleep 2000ms

# Manager tabs.
Right@1200ms 2
Sleep 1500ms

Type "q"
Sleep 800ms
