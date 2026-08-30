package ui

import (
	"strings"
	"testing"

	"github.com/Sousf/system-patch/internal/agent"
	"github.com/Sousf/system-patch/internal/model"
	"github.com/Sousf/system-patch/internal/sources"
)

// Ubuntu: apt is the only manager reporting repository packages, so the tab
// names it. "repo" is the Arch distinction between the official repositories
// and the AUR, and there is no AUR here.
func TestTabLabelNamesTheManager(t *testing.T) {
	ms := []sources.Manager{
		{Name: "apt", Origin: model.Repo},
		{Name: "snap", Origin: model.Snap},
	}
	if got := tabLabel(ms, model.Repo); got != "apt" {
		t.Errorf("repo tab = %q, want %q", got, "apt")
	}
	if got := tabLabel(ms, model.Snap); got != "snap" {
		t.Errorf("snap tab = %q, want %q", got, "snap")
	}
}

// Arch: one manager reports both halves, so it declares no single origin and
// both tabs keep the names that distinguish them. Labelling by manager would
// print "pacman + AUR" twice and lose the split that decides what a system
// upgrade rebuilds.
func TestTabLabelKeepsOriginWhenAManagerSpansTwo(t *testing.T) {
	ms := []sources.Manager{
		{Name: "pacman + AUR"}, // no Origin declared
		{Name: "flatpak", Origin: model.Flatpak},
	}
	if got := tabLabel(ms, model.Repo); got != "repo" {
		t.Errorf("repo tab = %q, want %q", got, "repo")
	}
	if got := tabLabel(ms, model.AUR); got != "aur" {
		t.Errorf("aur tab = %q, want %q", got, "aur")
	}
	if got := tabLabel(ms, model.Flatpak); got != "flatpak" {
		t.Errorf("flatpak tab = %q, want %q", got, "flatpak")
	}
}

// The label must not depend on what happens to be pending. An Arch machine
// with no AUR updates outstanding today has the same tab names as one with
// twenty, because the registry decides and the pending set does not.
func TestTabLabelIgnoresWhatIsPending(t *testing.T) {
	ms := []sources.Manager{{Name: "pacman + AUR"}}
	if got := tabLabel(ms, model.Repo); got != "repo" {
		t.Errorf("repo tab = %q, want %q", got, "repo")
	}
}

// A machine carrying two repository managers cannot be named by either.
func TestTabLabelFallsBackWhenManagersCollide(t *testing.T) {
	ms := []sources.Manager{
		{Name: "apt", Origin: model.Repo},
		{Name: "dnf", Origin: model.Repo},
	}
	if got := tabLabel(ms, model.Repo); got != "repo" {
		t.Errorf("repo tab = %q, want %q", got, "repo")
	}
}

// An origin no registry entry claims still has to render.
func TestTabLabelFallsBackWhenUnclaimed(t *testing.T) {
	if got := tabLabel(nil, model.Repo); got != "repo" {
		t.Errorf("repo tab = %q, want %q", got, "repo")
	}
	ms := []sources.Manager{{Name: "flatpak", Origin: model.Flatpak}}
	if got := tabLabel(ms, model.AUR); got != "aur" {
		t.Errorf("aur tab = %q, want %q", got, "aur")
	}
}

// The title and the tab bar total the same set, so they must agree. They did
// not: the title counted the synthetic whole-system row as a package.
func TestCountsExcludeTheSystemRow(t *testing.T) {
	real := []model.Update{
		{Name: "byobu", Origin: model.Repo, Manager: "apt"},
		{Name: "procps", Origin: model.Repo, Manager: "apt"},
		{Name: "openssl", Origin: model.Repo, Manager: "apt", CVEs: []string{"CVE-2026-1"}},
	}
	ups := append([]model.Update{agent.SystemEntry(real)}, real...)

	pending, flagged := counts(ups)
	if pending != 3 {
		t.Errorf("pending = %d, want 3 (the system row is not a package)", pending)
	}
	if flagged != 1 {
		t.Errorf("flagged = %d, want 1", flagged)
	}

	// The same total the tab bar renders, computed the way renderTabs does.
	tabTotal := 0
	for _, u := range ups {
		if !agent.IsSystem(u) {
			tabTotal++
		}
	}
	if pending != tabTotal {
		t.Errorf("title says %d, tabs say %d", pending, tabTotal)
	}
}

// Every registry entry that declares an origin must be the only one declaring
// it on any machine where both could be detected. The three pacman entries are
// mutually exclusive by Detect, so only the AUR-less one declares Repo.
func TestRegistryOriginsDoNotCollideOnOneMachine(t *testing.T) {
	seen := map[model.Origin][]string{}
	for _, m := range sources.Registry() {
		if m.Origin != "" {
			seen[m.Origin] = append(seen[m.Origin], m.Name)
		}
	}
	// apt, dnf and pacman all claim Repo, but no machine detects two of them:
	// apt requires /etc/debian_version, dnf requires the dnf binary, pacman
	// requires pacman without an AUR helper. This test documents the claim so
	// that adding a fourth is a deliberate act.
	if got := len(seen[model.Repo]); got != 3 {
		t.Errorf("managers declaring Repo = %v, want exactly apt, dnf, pacman", seen[model.Repo])
	}
}

// Every reason Flagged() recognises must render a mark and a line. Two call
// sites enumerated the set by hand and both had dropped a case, so a package
// flagged only as suspected printed blank while count counted it.
func TestEveryFlagReasonExplains(t *testing.T) {
	cases := []struct {
		name string
		u    model.Update
		want model.ReasonKind
	}{
		{"tracker", model.Update{CVEs: []string{"CVE-1"}, Severity: "High"}, model.ReasonTrackerCVE},
		{"tracker unrated", model.Update{CVEs: []string{"CVE-1"}}, model.ReasonTrackerCVE},
		{"upstream", model.Update{UpstreamCVEs: 3}, model.ReasonUpstreamCVE},
		{"maintainer", model.Update{MaintainerWas: "a", Maintainer: "b"}, model.ReasonMaintainer},
		{"suspected", model.Update{UpstreamKind: model.KindSuspected}, model.ReasonSuspected},
		{"out of date", model.Update{OutOfDate: true}, model.ReasonOutOfDate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.u.Reason(); got != c.want {
				t.Fatalf("Reason() = %v, want %v", got, c.want)
			}
			if !c.u.Flagged() {
				t.Error("Flagged() is false for a reason that has one")
			}
			if c.u.Explain() == "" {
				t.Error("Explain() is empty for a flagged update")
			}
		})
	}
	var clean model.Update
	if clean.Flagged() || clean.Reason() != model.ReasonNone || clean.Explain() != "" {
		t.Error("an unflagged update reported a reason")
	}
}

// An unrated advisory must not render as an empty severity.
func TestUnratedSeverityHasWords(t *testing.T) {
	u := model.Update{CVEs: []string{"CVE-1", "CVE-2"}}
	if got := u.Explain(); !strings.Contains(got, "unrated") {
		t.Errorf("Explain() = %q, want it to name the missing rating", got)
	}
}
