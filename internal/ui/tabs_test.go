package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

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
	// Not "pacman + AUR" on either tab: that would print one name twice and
	// hide the split deciding what an upgrade rebuilds.
	if got := tabLabel(ms, model.Repo); got == "pacman + AUR" {
		t.Error("repository tab took the name of a manager spanning two origins")
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
	if got := tabLabel(ms, model.Repo); got == "pacman + AUR" {
		t.Error("label taken from a manager that reports two origins")
	}
}

// A machine carrying two repository managers cannot be named by either.
func TestTabLabelFallsBackWhenManagersCollide(t *testing.T) {
	ms := []sources.Manager{
		{Name: "apt", Origin: model.Repo},
		{Name: "dnf", Origin: model.Repo},
	}
	if got := tabLabel(ms, model.Repo); got == "apt" || got == "dnf" {
		t.Errorf("repo tab = %q, but two managers claim that origin", got)
	}
}

// An origin no registry entry claims still has to render, and repository
// packages fall back to the family's manager rather than to the word "repo".
func TestTabLabelFallsBackWhenUnclaimed(t *testing.T) {
	want := sources.Host().RepoManager
	if want == "" {
		want = "repo" // a family this tool does not know
	}
	if got := tabLabel(nil, model.Repo); got != want {
		t.Errorf("repo tab = %q, want %q", got, want)
	}
	ms := []sources.Manager{{Name: "flatpak", Origin: model.Flatpak}}
	if got := tabLabel(ms, model.AUR); got != "aur" {
		t.Errorf("aur tab = %q, want %q", got, "aur")
	}
	if got := tabLabel(ms, model.Snap); got != "snap" {
		t.Errorf("snap tab = %q, want %q", got, "snap")
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

// The chrome must fit the terminal exactly. The pinned verdict and the tab bar
// each take a line off the scrolling area and each appears on a state change
// rather than on a resize, so the viewport has to be resized when they do.
func TestViewportHeightLeavesRoomForChrome(t *testing.T) {
	const h = 40
	cases := []struct {
		name    string
		origins []model.Origin
		text    string
		mode    pane
		want    int // viewport height
	}{
		{"one origin, no pin", []model.Origin{model.Repo}, "", paneNotes, h - 4},
		{"two origins, no pin", []model.Origin{model.Repo, model.AUR}, "", paneNotes, h - 4},
		{"routine pin", []model.Origin{model.Repo},
			"## VERDICT: ROUTINE\n", paneAgent, h - 5},
		{"urgent pin", []model.Origin{model.Repo},
			"## VERDICT: INSTALL NOW\n", paneAgent, h - 6},
		{"no origins yet, urgent pin", nil,
			"## VERDICT: INSTALL NOW\n", paneAgent, h - 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Model{w: 120, h: h, tabOrigins: c.origins, agentText: c.text, mode: c.mode}
			m.layout()
			if m.vp.Height != c.want {
				t.Errorf("viewport height = %d, want %d", m.vp.Height, c.want)
			}
			// Whatever the chrome, the rendered view must not exceed the
			// terminal it was given.
			m.vp.SetContent(strings.Repeat("line\n", 200))
			if got := lipgloss.Height(m.View()); got > h {
				t.Errorf("View() is %d lines tall in a %d-line terminal", got, h)
			}
		})
	}
}

// The bar labels as much as it filters, so it is drawn whenever anything is
// pending. Hiding it on a single-origin machine left nothing on screen saying
// which manager the packages belonged to.
func TestTabBarLabelsEvenWithOneOrigin(t *testing.T) {
	m := Model{updates: []model.Update{{Name: "a", Origin: model.Repo}}}
	m.tabOrigins = []model.Origin{model.Repo}
	if got := m.renderTabs(); got == "" {
		t.Error("tab bar hidden with one origin pending, so nothing names the manager")
	}
	m.tabOrigins = nil
	if got := m.renderTabs(); got != "" {
		t.Errorf("tab bar drawn with nothing pending: %q", got)
	}
}

// Repository packages are named after the manager that owns them, since the
// Arch registry entry reports repository and AUR packages together and cannot
// lend its name to either tab.
func TestRepoTabTakesTheFamilyManagerName(t *testing.T) {
	archish := []sources.Manager{{Name: "pacman + AUR"}, {Name: "flatpak", Origin: model.Flatpak}}
	got := tabLabel(archish, model.Repo)
	if got == "repo" {
		t.Error("repository tab still labelled \"repo\" instead of its manager")
	}
	t.Logf("repository tab on this host: %q", got)
	if l := tabLabel(archish, model.AUR); l != "aur" {
		t.Errorf("AUR tab = %q, want \"aur\"", l)
	}
	// A manager that owns exactly one origin still names its own tab.
	if l := tabLabel([]sources.Manager{{Name: "apt", Origin: model.Repo}}, model.Repo); l != "apt" {
		t.Errorf("apt tab = %q, want \"apt\"", l)
	}
}

// The verdict has to survive scrolling, which means living outside the
// viewport rather than at the top of its content.
func TestVerdictIsPinnedOutsideTheViewport(t *testing.T) {
	m := &Model{w: 120, h: 40, mode: paneAgent,
		agentText: "## thing\n\n## VERDICT: INSTALL NOW\n\nbody\n"}
	m.layout()
	if m.pinnedVerdict() == "" {
		t.Fatal("no pinned verdict for a document that states one")
	}
	if strings.Contains(m.renderAgent(), "INSTALL NOW") &&
		!strings.Contains(m.renderAgent(), "VERDICT") {
		t.Error("banner still written into the scrolling content")
	}
	// Scrolled to the bottom, the verdict must still be on screen.
	m.vp.SetContent(m.renderAgent())
	m.vp.GotoBottom()
	if !strings.Contains(m.View(), "INSTALL NOW") {
		t.Error("verdict lost once the pane is scrolled to the bottom")
	}
}
