package agent

import (
	"strings"
	"testing"

	"github.com/Sousf/system-patch/internal/sources"
)

func TestWrapKeepsLinesWithinWidth(t *testing.T) {
	// The Debian configuration convention, which is the longest string the
	// system brief interpolates and the one that overran before wrapping.
	long := "4. AFTERWARDS — reboots, service restarts, modified config files " +
		"prompt on upgrade, or are left as .dpkg-dist and .dpkg-new beside the " +
		"original when running non-interactively, and anything that will look " +
		"broken until a step is taken."

	got := wrap(long, 76, "   ")
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 76 {
			t.Errorf("line of %d chars exceeds 76:\n%s", len(line), line)
		}
	}
	if !strings.HasPrefix(got, "4. AFTERWARDS") {
		t.Errorf("first line lost its label: %q", got)
	}
	for _, line := range strings.Split(got, "\n")[1:] {
		if !strings.HasPrefix(line, "   ") {
			t.Errorf("continuation line not indented: %q", line)
		}
	}
	if strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(long), " ") {
		t.Error("wrapping changed the words")
	}
}

func TestWrapHandlesEdges(t *testing.T) {
	if got := wrap("", 10, "  "); got != "" {
		t.Errorf("empty input produced %q", got)
	}
	// A single word longer than the width has nowhere to break, and must be
	// emitted rather than dropped or looped over.
	long := strings.Repeat("x", 40)
	if got := wrap(long, 10, "  "); got != long {
		t.Errorf("overlong word mangled: %q", got)
	}
}

// A CVE count off Arch did not come from the Arch Security Tracker, and
// labelling it as though it did attributes data to a source never consulted.
func TestTrackerNameFollowsHost(t *testing.T) {
	if got := trackerName(sources.HostInfo{Family: sources.Arch}); got != "Arch tracker" {
		t.Errorf("arch: got %q", got)
	}
	if got := trackerName(sources.HostInfo{Family: sources.Debian}); got == "Arch tracker" {
		t.Errorf("debian: attributed to the Arch tracker")
	}
}
