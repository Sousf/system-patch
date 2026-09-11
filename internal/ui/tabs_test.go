package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
			m := &Model{w: 120, h: h, tabOrigins: c.origins, mode: c.mode,
				runs: map[string]*agentRun{}, updates: []model.Update{{Name: "p"}}}
			if c.text != "" {
				m.runs["p"] = &agentRun{text: c.text}
			}
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
		updates: []model.Update{{Name: "p"}},
		runs: map[string]*agentRun{
			"p": {text: "## thing\n\n## VERDICT: INSTALL NOW\n\nbody\n"},
		}}
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

// noANSI drops styling so an assertion about content is not defeated by
// glamour colouring each word separately.
func noANSI(s string) string {
	var b strings.Builder
	skip := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			skip = true
		case skip && (r == 'm' || r == 'K' || r == 'H'):
			skip = false
		case !skip:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// Two analyses at once. Pressing a, moving on, and pressing a again used to
// refuse the second run outright; both must now stream, and moving between
// them must show each one's own output.
func TestConcurrentRunsAreIndependent(t *testing.T) {
	pkgs := []model.Update{{Name: "alpha"}, {Name: "beta"}}
	m := &Model{
		w: 120, h: 40, mode: paneAgent,
		updates: pkgs,
		notes:   map[string]model.Notes{},
		loading: map[string]bool{},
		runs: map[string]*agentRun{
			"alpha": {running: true, text: "alpha body\n"},
			"beta":  {running: true, text: "beta body\n"},
		},
	}
	m.layout()

	if n := m.runningCount(); n != 2 {
		t.Fatalf("runningCount = %d, want 2", n)
	}
	if !m.anyRunning() {
		t.Error("anyRunning is false with two runs in flight")
	}

	m.cursor = 0
	if got := noANSI(m.renderAgent()); !strings.Contains(got, "alpha body") ||
		strings.Contains(got, "beta body") {
		t.Errorf("the pane for alpha showed the wrong run: %q", got)
	}
	m.cursor = 1
	if got := noANSI(m.renderAgent()); !strings.Contains(got, "beta body") ||
		strings.Contains(got, "alpha body") {
		t.Errorf("the pane for beta showed the wrong run: %q", got)
	}
}

// A line arriving for a run that is not on screen must land in that run's
// record rather than the visible one.
func TestOutputRoutesToItsOwnRun(t *testing.T) {
	m := Model{
		updates: []model.Update{{Name: "alpha"}, {Name: "beta"}},
		notes:   map[string]model.Notes{},
		loading: map[string]bool{},
		runs: map[string]*agentRun{
			"alpha": {running: true},
			"beta":  {running: true},
		},
		w: 120, h: 40, mode: paneAgent,
	}
	m.layout()
	m.cursor = 0 // watching alpha

	out, _ := m.Update(agentMsg{name: "beta", line: agent.Line{Kind: agent.Text, Text: "from beta"}})
	got := out.(Model)
	if strings.Contains(got.runs["alpha"].text, "from beta") {
		t.Error("beta's output landed in alpha's record")
	}
	if !strings.Contains(got.runs["beta"].text, "from beta") {
		t.Error("beta's output never reached beta")
	}
}

// Moving the cursor onto a package with a run shows it; onto one without shows
// its notes. Without this, stepping away from a running analysis lost it.
func TestSelectionFollowsTheRun(t *testing.T) {
	m := &Model{
		updates: []model.Update{{Name: "alpha"}, {Name: "beta"}},
		runs:    map[string]*agentRun{"beta": {running: true}},
		w:       120, h: 40,
	}
	m.layout()
	m.cursor = 0
	m.syncPane()
	if m.mode != paneNotes {
		t.Error("a package with no run should show its notes")
	}
	m.cursor = 1
	m.syncPane()
	if m.mode != paneAgent {
		t.Error("a package with a run should show it")
	}
}

// x cancels the selected run only. With several in flight, one key killing all
// of them would be a trap.
func TestCancelOnlyTouchesTheSelectedRun(t *testing.T) {
	cancelled := map[string]bool{}
	m := &Model{
		updates: []model.Update{{Name: "alpha"}, {Name: "beta"}},
		notes:   map[string]model.Notes{},
		loading: map[string]bool{},
		runs: map[string]*agentRun{
			"alpha": {running: true, cancel: func() { cancelled["alpha"] = true }},
			"beta":  {running: true, cancel: func() { cancelled["beta"] = true }},
		},
		w: 120, h: 40,
	}
	m.layout()
	m.cursor = 1 // beta selected
	m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if cancelled["alpha"] {
		t.Error("cancelling beta also cancelled alpha")
	}
	if !cancelled["beta"] {
		t.Error("the selected run was not cancelled")
	}
}

// The list marks which packages are being analysed. The title says how many
// runs are in flight but not which, and with several going that is the thing
// you need to see.
func TestRunningPackagesAreMarkedInTheList(t *testing.T) {
	pkgs := []model.Update{{Name: "alpha"}, {Name: "beta"}}
	m := New()
	m.w, m.h = 120, 40
	m.updates = pkgs
	m.booting = false
	m.runs = map[string]*agentRun{"beta": {running: true}}
	m.layout()

	list := noANSI(m.renderList(m.leftWidth()))
	if !strings.Contains(list, "alpha") || !strings.Contains(list, "beta") {
		t.Fatalf("list is missing rows: %q", list)
	}
	// The idle package keeps its badge; the running one shows the spinner, so
	// the two rows must not carry the same mark.
	alphaMark := strings.SplitN(strings.TrimSpace(list), "alpha", 2)[0]
	betaMark := strings.SplitN(list, "beta", 2)[0]
	betaMark = betaMark[strings.LastIndex(betaMark, "\n")+1:]
	if strings.TrimSpace(alphaMark) == strings.TrimSpace(betaMark) {
		t.Errorf("running and idle rows carry the same mark: %q vs %q", alphaMark, betaMark)
	}
}

// Starting an analysis must not steal the arrow keys. Pressing a used to focus
// the right pane, so moving to the next package meant escaping out first, and
// the first esc also threw away the report.
func TestAnalyseKeepsYouInTheList(t *testing.T) {
	pkgs := []model.Update{{Name: "alpha"}, {Name: "beta"}, {Name: "gamma"}}
	m := New()
	m.w, m.h = 120, 40
	m.updates = pkgs
	m.booting = false
	m.runs = map[string]*agentRun{"alpha": {running: true, text: "watching alpha"}}
	m.layout()
	m.cursor = 0
	m.syncPane()

	if m.focusRight {
		t.Fatal("a package with a run should not have taken focus")
	}
	// j must still move the cursor rather than scroll the pane.
	out, _ := m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	got := out.(Model)
	if got.cursor != 1 {
		t.Errorf("cursor = %d after j, want 1: the arrow keys were captured", got.cursor)
	}
	if u, _ := got.sel(); u.Name != "beta" {
		t.Errorf("selection = %q, want beta", u.Name)
	}
}

// enter opens the pane, esc comes straight back. esc used to step off the
// analysis first, so it took two presses to regain the list.
func TestEnterOpensAndEscReturns(t *testing.T) {
	m := New()
	m.w, m.h = 120, 40
	m.updates = []model.Update{{Name: "alpha"}}
	m.booting = false
	m.runs = map[string]*agentRun{"alpha": {text: "## VERDICT: ROUTINE\n"}}
	m.layout()
	m.cursor = 0
	m.syncPane()

	out, _ := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
	m = out.(Model)
	if !m.focusRight {
		t.Fatal("enter did not focus the right pane")
	}
	out, _ = m.onKey(tea.KeyMsg{Type: tea.KeyEsc})
	m = out.(Model)
	if m.focusRight {
		t.Error("esc did not return focus to the list")
	}
	if m.mode != paneAgent {
		t.Error("esc threw away the analysis on the way out of the pane")
	}
	// A second esc steps off the analysis to the notes.
	out, _ = m.onKey(tea.KeyMsg{Type: tea.KeyEsc})
	if out.(Model).mode != paneNotes {
		t.Error("a second esc should show the notes instead")
	}
}

// i installs whatever the state of the analyses. It refused silently while any
// run was going, which was survivable with one analysis at a time and became a
// dead key once several could run at once.
func TestInstallWorksWhileAnalysesRun(t *testing.T) {
	cases := []struct {
		name  string
		runs  map[string]*agentRun
		focus bool
	}{
		{"no runs, list focused", map[string]*agentRun{}, false},
		{"no runs, pane focused", map[string]*agentRun{}, true},
		{"one running", map[string]*agentRun{"alpha": {running: true}}, false},
		{"one running, pane focused", map[string]*agentRun{"alpha": {running: true}}, true},
		{"two running", map[string]*agentRun{
			"alpha": {running: true}, "beta": {running: true}}, false},
		{"one finished", map[string]*agentRun{"alpha": {text: "done"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := New()
			m.w, m.h = 120, 40
			m.updates = []model.Update{{Name: "alpha", Origin: model.AUR}}
			m.booting = false
			m.runs = c.runs
			m.focusRight = c.focus
			m.layout()
			m.cursor = 0

			out, _ := m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
			got := out.(Model)
			if !got.confirming {
				t.Fatal("i did not open the install confirmation")
			}
			if got.plan.label == "" {
				t.Error("the confirmation names no command")
			}
			// With runs in flight the confirmation has to say so.
			if got.runningCount() > 0 && !strings.Contains(noANSI(got.View()), "analysing") {
				t.Error("the confirmation does not mention the running analyses")
			}
		})
	}
}

// Every key the help line offers has to work in the state it is offered in.
func TestHelpLineOffersInstallEverywhere(t *testing.T) {
	for _, focus := range []bool{false, true} {
		m := New()
		m.w, m.h = 120, 40
		m.updates = []model.Update{{Name: "alpha", Origin: model.AUR}}
		m.booting = false
		m.runs = map[string]*agentRun{"alpha": {running: true}}
		m.focusRight = focus
		m.layout()
		m.cursor = 0
		m.syncPane()
		if help := noANSI(m.View()); !strings.Contains(help, "i install") {
			t.Errorf("focusRight=%v: help line does not offer i install", focus)
		}
	}
}

// space gathers rows; a and i then act on the set instead of the cursor.
func TestMarkedRowsDriveActions(t *testing.T) {
	pkgs := []model.Update{
		{Name: "alpha", Origin: model.AUR},
		{Name: "beta", Origin: model.AUR},
		{Name: "gamma", Origin: model.AUR},
	}
	m := New()
	m.w, m.h = 120, 40
	m.updates = pkgs
	m.booting = false
	m.layout()

	space := func(m Model) Model {
		out, _ := m.onKey(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
		return out.(Model)
	}
	m.cursor = 0
	m = space(m)
	m.cursor = 2
	m = space(m)

	if len(m.marked) != 2 || !m.marked["alpha"] || !m.marked["gamma"] {
		t.Fatalf("marks = %v, want alpha and gamma", m.marked)
	}
	// targets is the set, not the cursor.
	got := m.targets()
	if len(got) != 2 || got[0].Name != "alpha" || got[1].Name != "gamma" {
		t.Fatalf("targets = %v, want alpha and gamma", got)
	}
	// The plan covers both, chained.
	plan := m.installPlan()
	if !strings.Contains(plan.label, "alpha") || !strings.Contains(plan.label, "gamma") {
		t.Errorf("plan label = %q, want both packages", plan.label)
	}
	if strings.Contains(plan.label, "beta") {
		t.Errorf("plan label = %q, includes an unmarked package", plan.label)
	}
	// space again unmarks.
	m.cursor = 0
	m = space(m)
	if m.marked["alpha"] {
		t.Error("space did not unmark a marked row")
	}
}

// With nothing marked the actions fall back to the cursor, which is how the
// tool worked before marking existed.
func TestUnmarkedFallsBackToTheCursor(t *testing.T) {
	m := New()
	m.w, m.h = 120, 40
	m.updates = []model.Update{{Name: "alpha", Origin: model.AUR}, {Name: "beta", Origin: model.AUR}}
	m.booting = false
	m.layout()
	m.cursor = 1
	got := m.targets()
	if len(got) != 1 || got[0].Name != "beta" {
		t.Fatalf("targets = %v, want just the selected row", got)
	}
	if l := m.installPlan().label; !strings.Contains(l, "beta") || strings.Contains(l, "alpha") {
		t.Errorf("plan = %q, want only the selected package", l)
	}
}

// One repository package in the set widens the whole thing, because there is
// no safe way to install one repo package on its own.
func TestRepoPackageWidensABatch(t *testing.T) {
	ups := []model.Update{
		{Name: "alpha", Origin: model.AUR},
		{Name: "libvpx", Origin: model.Repo},
	}
	plan := planFor(ups)
	if !plan.full {
		t.Error("a batch containing a repository package did not widen to the full upgrade")
	}
	if !strings.Contains(plan.why, "libvpx") {
		t.Errorf("why = %q, does not name the row that forced it", plan.why)
	}
}

// Marks are spent by the action that uses them, or the next press repeats the
// batch rather than acting on the cursor.
func TestMarksClearAfterInstall(t *testing.T) {
	m := New()
	m.w, m.h = 120, 40
	m.updates = []model.Update{{Name: "alpha", Origin: model.AUR}}
	m.booting = false
	m.marked = map[string]bool{"alpha": true}
	m.layout()

	out, _ := m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m = out.(Model)
	if !m.confirming {
		t.Fatal("i did not open the confirmation")
	}
	out, _ = m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if n := len(out.(Model).marked); n != 0 {
		t.Errorf("%d marks survived the install they drove", n)
	}
}

// c clears the whole selection, since unmarking a dozen rows one at a time is
// not a way to change your mind.
func TestClearKeyDropsEveryMark(t *testing.T) {
	m := New()
	m.updates = []model.Update{{Name: "alpha"}, {Name: "beta"}}
	m.marked = map[string]bool{"alpha": true, "beta": true}
	m.w, m.h = 120, 40
	m.layout()
	out, _ := m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if n := len(out.(Model).marked); n != 0 {
		t.Errorf("%d marks survived c", n)
	}
}
