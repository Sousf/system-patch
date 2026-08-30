package model

import "testing"

// UpstreamVersion is the shared half of what used to be two copies, one in
// VParts and one in the adapters' tag builder. The adapters copy cut an epoch
// without checking for a hyphen first, so these cases pin the careful rule.
func TestUpstreamVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.23.1-4", "1.23.1"},
		{"2:0.41.0-6", "0.41.0"},                     // pacman epoch
		{"v1.4.2", "1.4.2"},                          // forge tag
		{"1:3.6.3-1", "3.6.3"},                       // epoch and pkgrel together
		{"3.12.3-1ubuntu0.16", "3.12.3-1ubuntu0.16"}, // no trailing -N to strip
		{"  1.2.3  ", "1.2.3"},
		{"1.28.6-2", "1.28.6"},
		// A hyphen before the colon means the colon is not an epoch marker.
		{"foo-bar:1.2", "foo-bar:1.2"},
	}
	for _, c := range cases {
		if got := UpstreamVersion(c.in); got != c.want {
			t.Errorf("UpstreamVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVParts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"1.23.1-4", []int{1, 23, 1}},
		{"v2.17.0", []int{2, 17, 0}},
		{"1:0.41.0-6", []int{0, 41, 0}},
		{"152.0.7977.64-1", []int{152, 0, 7977, 64}},
		{"not-a-version", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := VParts(c.in)
		if len(got) != len(c.want) {
			t.Errorf("VParts(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("VParts(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

// Release ordering decides which entries fall between installed and available,
// so a wrong answer here silently drops or invents release notes.
func TestVCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign
	}{
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"1.2.0", "1.2.0", 0},
		{"1.2", "1.2.1", -1},   // shorter prefixes sort lower
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
		{"2.0", "10.0", -1},
	}
	for _, c := range cases {
		got := VCmp(VParts(c.a), VParts(c.b))
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("VCmp(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNotesReason(t *testing.T) {
	if got := (Notes{Err: "404 from the forge"}).Reason(); got != "404 from the forge" {
		t.Errorf("Reason() = %q, want the error", got)
	}
	// An empty Err is not a failure: it means upstream publishes nothing, and
	// the two must never render identically.
	if got := (Notes{}).Reason(); got == "" || got == "404 from the forge" {
		t.Errorf("Reason() = %q, want the no-notes wording", got)
	}
}

func TestOriginSystem(t *testing.T) {
	for _, o := range []Origin{Repo, AUR} {
		if !o.System() {
			t.Errorf("%q should be owned by the system package manager", o)
		}
	}
	for _, o := range []Origin{Flatpak, Snap} {
		if o.System() {
			t.Errorf("%q is a separate manager and its packages are not in the system database", o)
		}
	}
}
