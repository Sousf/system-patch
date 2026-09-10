// Package ui is the two-pane terminal interface.
//
// Left: every pending update, most consequential first. Right: why that update
// exists — upstream release notes, tracker CVEs, provenance — or the live
// output of an agent reading the source diff.
//
// Notes are fetched lazily on selection and cached on disk by version pair, so
// moving through the list costs one request per package per version, once.
package ui

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Sousf/system-patch/internal/adapters"
	"github.com/Sousf/system-patch/internal/agent"
	"github.com/Sousf/system-patch/internal/model"
	"github.com/Sousf/system-patch/internal/render"
	"github.com/Sousf/system-patch/internal/sources"
)

// Palette. Adaptive so the tool stays legible on a light terminal, which the
// rest of this machine's theming can switch to at any time.
var (
	cRed    = lipgloss.AdaptiveColor{Light: "#b4261e", Dark: "#f38ba8"}
	cYellow = lipgloss.AdaptiveColor{Light: "#8a6d00", Dark: "#f9e2af"}
	cGreen  = lipgloss.AdaptiveColor{Light: "#2c6e2c", Dark: "#a6e3a1"}
	cBlue   = lipgloss.AdaptiveColor{Light: "#1f5fa9", Dark: "#89b4fa"}
	cMauve  = lipgloss.AdaptiveColor{Light: "#7a3fb8", Dark: "#cba6f7"}
	cDim    = lipgloss.AdaptiveColor{Light: "#6c6f85", Dark: "#7f849c"}
	cText   = lipgloss.AdaptiveColor{Light: "#1e1e2e", Dark: "#cdd6f4"}

	stTitle  = lipgloss.NewStyle().Bold(true).Foreground(cMauve)
	stDim    = lipgloss.NewStyle().Foreground(cDim)
	stSel    = lipgloss.NewStyle().Bold(true).Foreground(cText)
	stRed    = lipgloss.NewStyle().Foreground(cRed)
	stYellow = lipgloss.NewStyle().Foreground(cYellow)
	stGreen  = lipgloss.NewStyle().Foreground(cGreen)
	stBlue   = lipgloss.NewStyle().Foreground(cBlue)
	stMauve  = lipgloss.NewStyle().Foreground(cMauve)
	stBold   = lipgloss.NewStyle().Bold(true)

	stRedBold    = lipgloss.NewStyle().Bold(true).Foreground(cRed)
	stYellowBold = lipgloss.NewStyle().Bold(true).Foreground(cYellow)
	stGreenBold  = lipgloss.NewStyle().Bold(true).Foreground(cGreen)

	stLeft = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, true, false, false).
		BorderForeground(cDim).PaddingRight(1)
)

type pane int

const (
	paneNotes pane = iota
	paneAgent
)

// rowLines is how many terminal lines one list entry occupies: the name, then
// the version delta and the reason it is flagged.
const rowLines = 2

type collectedMsg sources.Result
type notesMsg struct {
	name  string
	notes model.Notes
}

// agentMsg is one line from one run. The name is what makes several runs
// possible: bubbletea delivers every command's message to the same Update, so
// without it two analyses streaming at once would interleave into whichever
// pane happened to be open.
type agentMsg struct {
	name string
	line agent.Line
}

// agentRun is one analysis. Kept per package so pressing a, moving on, and
// pressing a again leaves both running rather than refusing the second.
type agentRun struct {
	out       []agent.Line
	text      string
	err       string
	running   bool
	fromCache bool
	ch        <-chan agent.Line
	cancel    context.CancelFunc
	start     time.Time
}

// Model is the bubbletea model.
type Model struct {
	updates  []model.Update
	warnings []string
	cursor   int

	notes   map[string]model.Notes
	loading map[string]bool

	vp      viewport.Model
	sp      spinner.Model
	w, h    int
	ready   bool
	booting bool

	mode       pane
	focusRight bool
	// runs holds every analysis started this session, keyed by package name.
	// Several may be running at once; the pane shows the selected package's.
	runs map[string]*agentRun

	// Tab state: 0 is the combined view, i>0 selects tabOrigins[i-1]. The
	// cursor indexes the visible (filtered) list, not m.updates.
	tab        int
	tabOrigins []model.Origin

	// Survives the rescan an upgrade triggers, which overwrites warnings, so a
	// failed upgrade is still on screen once the new list lands.
	upgradeErr string

	// Set while the install confirmation is on screen, holding what y runs.
	confirming bool
	plan       installPlan
}

// run is the analysis for the selected package, or nil.
func (m Model) run() *agentRun {
	u, ok := m.sel()
	if !ok {
		return nil
	}
	return m.runs[u.Name]
}

// anyRunning reports whether any analysis is still going, wherever it is.
func (m Model) anyRunning() bool {
	for _, r := range m.runs {
		if r.running {
			return true
		}
	}
	return false
}

// runningCount is how many analyses are in flight, for the title.
func (m Model) runningCount() int {
	n := 0
	for _, r := range m.runs {
		if r.running {
			n++
		}
	}
	return n
}

// syncPane points the right pane at whatever the newly selected package has.
//
// A package with a run shows it, whether or not that run has finished; one
// without shows its notes. Without this, moving the cursor off a running
// analysis and back again lost it.
func (m *Model) syncPane() {
	if m.run() != nil {
		m.mode = paneAgent
		return
	}
	m.mode = paneNotes
}

// upgradeSteps is every manager the full upgrade has to drive, in order.
//
// Detected rather than hardcoded, so "full system upgrade" means every manager
// actually installed here and not just the one Arch ships. Single-package
// installs are handled separately by installPlan, which knows which origins
// have a safe per-package path and which do not.
func upgradeSteps() [][]string {
	var steps [][]string
	for _, m := range sources.Managers() {
		steps = append(steps, m.Upgrade)
	}
	return steps
}

// upgradeCmd renders the steps as one shell line, for display and execution.
//
// Chained with && rather than ;: if a manager fails, or you abort at its
// confirmation prompt, that is a decision not to upgrade, and running the next
// one anyway would ignore it.
func upgradeCmd() []string {
	steps := upgradeSteps()
	if len(steps) == 0 {
		return []string{"true"}
	}
	if len(steps) == 1 {
		return steps[0]
	}
	var parts []string
	for _, s := range steps {
		parts = append(parts, shellJoin(s))
	}
	return []string{"sh", "-c", strings.Join(parts, " && ")}
}

// shellJoin quotes any argument that would otherwise be split or expanded.
//
// Needed because one of these commands is a Lua snippet full of spaces,
// braces and parentheses; pasted raw into `sh -c` it becomes several broken
// arguments instead of one.
func shellJoin(argv []string) string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\n\"'$&|;<>(){}*?[]!#~`\\") {
			out = append(out, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		} else {
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

// upgradeLabel names the managers rather than spelling out every command, so
// the confirmation stays readable when one of them is a Lua one-liner.
func upgradeLabel() string {
	ms := sources.Managers()
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		names = append(names, m.Name)
	}
	return strings.Join(names, " + ")
}

// installPlan is what pressing the install key will actually run, decided by
// what is selected. The distinction matters because "install just this one"
// is safe for some origins and a footgun for others:
//
//   - An AUR package builds against the system as it stands — no database
//     sync, no partial upgrade. `paru -S name` is safe and is what you meant.
//   - A flatpak ref is independent by design; updating one app is the normal
//     way to use flatpak.
//   - A repository package has NO safe single-package path: getting the new
//     version requires syncing the database, and installing one package from
//     a synced database is the partial-upgrade breakage Arch warns about.
//     Selecting one therefore still offers the full upgrade, and the
//     confirmation says why rather than silently widening the request.
type installPlan struct {
	argv  []string
	label string
	// full marks the whole-system chain across every manager.
	full bool
	// why explains a widened plan, shown in the confirmation.
	why string
}

func (m *Model) installPlan() installPlan {
	u, ok := m.sel()
	if !ok || agent.IsSystem(u) {
		return installPlan{argv: upgradeCmd(), label: upgradeLabel(), full: true}
	}
	switch u.Origin {
	case model.AUR:
		return installPlan{
			argv:  []string{"paru", "-S", u.Name},
			label: "paru -S " + u.Name,
		}
	case model.Flatpak:
		// The row is app/branch; flatpak addresses updates by application id
		// and updates every installed branch of it, which is what you want —
		// two branches of one runtime deliberately move together.
		app, _, _ := strings.Cut(u.Name, "/")
		return installPlan{
			argv:  []string{"flatpak", "update", app},
			label: "flatpak update " + app,
		}
	case model.Snap:
		return installPlan{
			argv:  []string{"sudo", "snap", "refresh", u.Name},
			label: "sudo snap refresh " + u.Name,
		}
	}
	return installPlan{
		argv:  upgradeCmd(),
		label: upgradeLabel(),
		full:  true,
		why: u.Name + " is a repository package, and one repo package cannot " +
			"be safely installed alone (partial upgrade)",
	}
}

type upgradeDoneMsg struct{ err error }

// runUpgrade hands the terminal to the package manager.
//
// tea.ExecProcess suspends the interface for the duration: the upgrade needs a
// real terminal for the sudo password and for pacman's own conflict and
// replacement prompts. Answering those blind through a captured pipe is how
// people confirm things they did not read.
func runUpgrade(argv []string) tea.Cmd {
	c := exec.Command(argv[0], argv[1:]...)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return upgradeDoneMsg{err: err}
	})
}

// New builds the initial model.
//
// Sized to a conventional 80x24 up front rather than waiting for the first
// WindowSizeMsg. Most terminals send one immediately, but a pty with no size
// set never does, and a UI that renders nothing at all until a message that
// may never arrive is indistinguishable from a hang.
func New() Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(cMauve)
	m := Model{
		notes:   map[string]model.Notes{},
		loading: map[string]bool{},
		runs:    map[string]*agentRun{},
		sp:      sp,
		booting: true,
		w:       80,
		h:       24,
	}
	m.layout()
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.sp.Tick, collect)
}

// collect reuses a recent enumeration so a second launch is instant. R forces
// recollect, which always re-syncs.
func collect() tea.Msg { return collectedMsg(sources.Load(10 * time.Minute)) }

func recollect() tea.Msg { return collectedMsg(sources.Collect()) }

// notesSem bounds how many note fetches are in flight.
//
// Each keypress that moves the cursor dispatches its own command, and nothing
// cancels the fetch for a row already scrolled past, so holding j through a
// cold list opened one request per package at once. Unauthenticated GitHub
// allows 60 an hour. The startup enrichment pass already caps itself at six
// for the same reason; this is the interactive path, which a user can trigger
// far faster than that one runs.
var notesSem = make(chan struct{}, 6)

func fetchNotes(u model.Update, refresh bool) tea.Cmd {
	return func() tea.Msg {
		notesSem <- struct{}{}
		defer func() { <-notesSem }()
		return notesMsg{name: u.Name, notes: adapters.For(u, refresh)}
	}
}

// waitAgent pumps one line off the agent's channel per Cmd, re-arming itself
// until the channel closes. This is how a streaming subprocess is folded into
// bubbletea's single-threaded update loop without blocking it.
func waitAgent(name string, ch <-chan agent.Line) tea.Cmd {
	return func() tea.Msg {
		l, ok := <-ch
		if !ok {
			return agentMsg{name: name, line: agent.Line{Done: true}}
		}
		return agentMsg{name: name, line: l}
	}
}

// visible is the list the cursor moves through: everything on the combined
// tab, one manager's rows on the others. The synthetic whole-system row lives
// only on the combined tab — it is not a package from any single manager.
func (m *Model) visible() []model.Update {
	if m.tab == 0 || m.tab > len(m.tabOrigins) {
		return m.updates
	}
	want := m.tabOrigins[m.tab-1]
	var out []model.Update
	for _, u := range m.updates {
		if u.Origin == want {
			out = append(out, u)
		}
	}
	return out
}

func (m *Model) sel() (model.Update, bool) {
	v := m.visible()
	if m.cursor < 0 || m.cursor >= len(v) {
		return model.Update{}, false
	}
	return v[m.cursor], true
}

// setTab switches tabs, resetting the cursor: an index into one filtered list
// is meaningless in another.
func (m *Model) setTab(t int) tea.Cmd {
	n := len(m.tabOrigins) + 1
	m.tab = ((t % n) + n) % n
	m.cursor = 0
	m.mode = paneNotes
	cmd := m.ensureNotes()
	m.refreshPane()
	m.vp.GotoTop()
	return cmd
}

// ensureNotes fetches the selected package's notes if they are not already in
// hand. Called on every cursor move; the disk cache makes repeats free.
func (m *Model) ensureNotes() tea.Cmd {
	u, ok := m.sel()
	if !ok || agent.IsSystem(u) {
		return nil
	}
	if _, have := m.notes[u.Name]; have || m.loading[u.Name] {
		return nil
	}
	m.loading[u.Name] = true
	return fetchNotes(u, false)
}

func (m *Model) layout() {
	lw := m.leftWidth()
	rw := m.w - lw - 3
	if rw < 20 {
		rw = 20
	}
	// Chrome: title, tab bar, and below the body a blank line and the help.
	// The tab bar is omitted when there is nothing to switch between, and the
	// pinned verdict takes its lines off the top of the scrolling area.
	vh := m.h - 4
	if !m.hasTabs() {
		vh++
	}
	vh -= m.pinHeight()
	if vh < 3 {
		vh = 3
	}
	if !m.ready {
		m.vp = viewport.New(rw, vh)
		m.ready = true
	} else {
		m.vp.Width, m.vp.Height = rw, vh
	}
}

// hasTabs reports whether the tab bar is drawn.
func (m Model) hasTabs() bool { return len(m.tabOrigins) > 0 }

// pinHeight is how many lines the pinned verdict occupies.
//
// Computed from the verdict alone rather than by rendering it, because layout
// needs the height before it has set the width the banner would be rendered
// at.
func (m Model) pinHeight() int {
	r := m.run()
	if m.mode != paneAgent || r == nil || r.text == "" {
		return 0
	}
	v, ok := render.FindVerdict(r.text)
	if !ok {
		return 0
	}
	if render.Urgency(v) > 0 {
		return 2 // the install hint rides with it
	}
	return 1
}

// pinnedVerdict is the verdict held above the scrolling pane.
//
// Outside the viewport, not the first line of its content. Inside it the
// banner scrolled away with everything else, so the one line worth reading
// was gone by the time you had read the evidence under it.
func (m Model) pinnedVerdict() string {
	if m.pinHeight() == 0 {
		return ""
	}
	v, _ := render.FindVerdict(m.run().text)
	out := verdictBanner(v, m.vp.Width)
	if render.Urgency(v) > 0 {
		out += "\n" + stDim.Render("  i to install (confirms first)")
	}
	return out
}

func (m Model) leftWidth() int {
	lw := m.w / 3
	if lw < 28 {
		lw = 28
	}
	if lw > 46 {
		lw = 46
	}
	return lw
}

func (m *Model) refreshPane() {
	// Re-run first: the pinned verdict and the tab bar both take lines off the
	// viewport, and both appear on state changes rather than on a resize. A
	// viewport still sized for the old chrome overruns the terminal by however
	// many lines the pin occupies.
	m.layout()
	if m.mode == paneAgent {
		m.vp.SetContent(m.renderAgent())
		return
	}
	m.vp.SetContent(m.renderNotes())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// A pty with no size configured reports 0x0. Taking that literally
		// collapses every pane to nothing and looks exactly like a hang, so
		// the constructor's default is kept instead.
		if msg.Width > 0 && msg.Height > 0 {
			m.w, m.h = msg.Width, msg.Height
			m.layout()
			m.refreshPane()
		}

	case spinner.TickMsg:
		if m.booting || m.anyRunning() || len(m.loading) > 0 {
			var c tea.Cmd
			m.sp, c = m.sp.Update(msg)
			cmds = append(cmds, c)

			// The spinner is drawn inside the viewport's content, and a
			// viewport only redraws what it was last given. Advancing the
			// spinner without re-rendering the pane left a frozen frame on
			// screen through every gap between tool calls — precisely the
			// stretches where the agent is thinking and the reader most needs
			// to see it is still alive.
			if r := m.run(); r != nil && r.running && m.mode == paneAgent {
				atBottom := m.vp.AtBottom()
				m.refreshPane()
				if atBottom {
					m.vp.GotoBottom()
				}
			}
		}

	case collectedMsg:
		m.booting = false
		// The whole-transaction row leads the list. "Is it safe to upgrade
		// everything right now" is the question a per-package view never
		// answers, and it is usually the one being asked.
		m.updates = append([]model.Update{agent.SystemEntry(msg.Updates)}, msg.Updates...)
		m.warnings = msg.Warnings
		// One tab per origin actually present, in the same rank order as the
		// list itself. Derived from the data, not the registry, so a manager
		// with nothing pending does not get an empty tab.
		seen := map[model.Origin]bool{}
		m.tabOrigins = nil
		for _, u := range msg.Updates {
			if !seen[u.Origin] {
				seen[u.Origin] = true
				m.tabOrigins = append(m.tabOrigins, u.Origin)
			}
		}
		m.tab = 0
		m.cursor = 0
		if cmd := m.ensureNotes(); cmd != nil {
			cmds = append(cmds, cmd)
		}
		m.refreshPane()

	case notesMsg:
		delete(m.loading, msg.name)
		m.notes[msg.name] = msg.notes
		if u, ok := m.sel(); ok && u.Name == msg.name && m.mode == paneNotes {
			m.refreshPane()
		}

	case agentMsg:
		r := m.runs[msg.name]
		if r == nil {
			break // its run was cleared out from under it
		}
		if msg.line.Kind == agent.Text {
			// Blank text lines are kept: they are the paragraph breaks that
			// make the Markdown parse as separate blocks.
			r.text += msg.line.Text + "\n"
		} else if msg.line.Text != "" {
			r.out = append(r.out, msg.line)
		}
		if msg.line.Done {
			r.running = false
			r.ch = nil
			if msg.line.Err != nil && msg.line.Err != context.Canceled {
				r.err = msg.line.Err.Error()
			}
			m.saveAnalysis(msg.name)
		} else if r.ch != nil {
			cmds = append(cmds, waitAgent(msg.name, r.ch))
		}
		// Only the pane actually on screen is re-rendered. A run streaming
		// behind another package's pane costs nothing to keep filling.
		sel, selOK := m.sel()
		if m.mode == paneAgent && selOK && sel.Name == msg.name {
			atBottom := m.vp.AtBottom()
			m.refreshPane()
			// Follow the tail only while the reader is already at the bottom,
			// so scrolling back to reread something is not yanked away by the
			// next line of output.
			if atBottom {
				m.vp.GotoBottom()
			}
		}

	case upgradeDoneMsg:
		// The package database moved, so every pending-update answer just
		// became wrong. Re-enumerate rather than leave the list describing a
		// system that no longer exists.
		m.booting = true
		m.upgradeErr = ""
		if msg.err != nil {
			m.upgradeErr = "upgrade: " + msg.err.Error()
		}
		return m, tea.Batch(recollect, m.sp.Tick)

	case tea.KeyMsg:
		return m.onKey(msg)
	}

	if m.ready {
		var c tea.Cmd
		m.vp, c = m.vp.Update(msg)
		cmds = append(cmds, c)
	}
	return m, tea.Batch(cmds...)
}

func (m Model) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// The confirmation swallows every key while it is up, so a stray
	// navigation press cannot fall through and start an upgrade.
	if m.confirming {
		switch msg.String() {
		case "y", "Y":
			m.confirming = false
			return m, runUpgrade(m.plan.argv)
		default:
			m.confirming = false
			return m, nil
		}
	}

	switch msg.String() {
	case "q", "ctrl+c":
		for _, r := range m.runs {
			if r.cancel != nil {
				r.cancel()
			}
		}
		return m, tea.Quit

	case "esc":
		// One key that always steps back: out of the agent pane, then out of
		// right-pane focus.
		if m.mode == paneAgent {
			m.mode = paneNotes
			m.refreshPane()
			m.vp.GotoTop()
		} else {
			m.focusRight = false
		}
		return m, nil

	case "tab":
		m.focusRight = !m.focusRight
		return m, nil

	case "j", "down":
		if m.focusRight {
			break
		}
		if m.cursor < len(m.visible())-1 {
			m.cursor++
			m.syncPane()
			if cmd := m.ensureNotes(); cmd != nil {
				cmds = append(cmds, cmd)
			}
			m.refreshPane()
			m.vp.GotoTop()
		}
		return m, tea.Batch(cmds...)

	case "k", "up":
		if m.focusRight {
			break
		}
		if m.cursor > 0 {
			m.cursor--
			m.syncPane()
			if cmd := m.ensureNotes(); cmd != nil {
				cmds = append(cmds, cmd)
			}
			m.refreshPane()
			m.vp.GotoTop()
		}
		return m, tea.Batch(cmds...)

	case "g":
		if !m.focusRight && len(m.visible()) > 0 {
			m.cursor = 0
			m.syncPane()
			if cmd := m.ensureNotes(); cmd != nil {
				cmds = append(cmds, cmd)
			}
			m.refreshPane()
		}
		return m, tea.Batch(cmds...)

	case "G":
		if !m.focusRight && len(m.visible()) > 0 {
			m.cursor = len(m.visible()) - 1
			m.syncPane()
			if cmd := m.ensureNotes(); cmd != nil {
				cmds = append(cmds, cmd)
			}
			m.refreshPane()
		}
		return m, tea.Batch(cmds...)

	case "r":
		// Force a re-read of this package's notes, bypassing the cache.
		if u, ok := m.sel(); ok {
			m.loading[u.Name] = true
			delete(m.notes, u.Name)
			m.mode = paneNotes
			m.refreshPane()
			return m, tea.Batch(fetchNotes(u, true), m.sp.Tick)
		}

	case "R":
		m.booting = true
		m.notes = map[string]model.Notes{}
		return m, tea.Batch(recollect, m.sp.Tick)

	case "enter":
		// Deliberately not the analyse key. Enter is the most-pressed key in
		// any list, and an agent run costs minutes and real tokens; that
		// belongs behind a key you meant to press.
		m.focusRight = true
		return m, nil

	case "h", "left":
		if !m.focusRight {
			return m, m.setTab(m.tab - 1)
		}

	case "l", "right":
		if !m.focusRight {
			return m, m.setTab(m.tab + 1)
		}

	case "a":
		return m.startAgent(false)

	case "A":
		// Explicit re-run, bypassing the stored answer. Separate from `a` so
		// spending again is always deliberate.
		return m.startAgent(true)

	case "i":
		// Upgrading moves the system under every running analysis, so the
		// answers they are still deriving would describe a machine that no
		// longer exists.
		if m.anyRunning() {
			return m, nil
		}
		m.plan = m.installPlan()
		m.confirming = true
		return m, nil

	case "x":
		// Cancels the selected package's run, not every run: with several in
		// flight, one key that killed all of them would be a trap.
		if r := m.run(); r != nil && r.running && r.cancel != nil {
			r.cancel()
		}
		return m, nil
	}

	if m.ready && m.focusRight {
		var c tea.Cmd
		m.vp, c = m.vp.Update(msg)
		cmds = append(cmds, c)
	}
	return m, tea.Batch(cmds...)
}

func (m Model) startAgent(force bool) (tea.Model, tea.Cmd) {
	u, ok := m.sel()
	if !ok {
		return m, nil
	}

	// Already running: show it rather than starting a second copy of the same
	// analysis. A concurrent tool still has no reason to pay twice for one
	// answer, and this is what pressing a on a package you already started
	// should do.
	if r := m.runs[u.Name]; r != nil && r.running && !force {
		m.mode = paneAgent
		m.focusRight = true
		m.refreshPane()
		return m, nil
	}
	// A forced re-run replaces whatever was there, so the old process has to
	// go or it keeps streaming into the record its replacement now owns.
	if r := m.runs[u.Name]; r != nil && r.running && r.cancel != nil {
		r.cancel()
	}

	r := &agentRun{}
	m.runs[u.Name] = r
	m.mode = paneAgent

	// A stored analysis for these exact versions is shown rather than
	// re-derived. The run costs real money and the answer cannot have changed
	// while both version numbers stayed the same.
	if !force {
		if s, hit := agent.LoadStored(u); hit {
			r.text = s.Text
			r.fromCache = true
			for _, t := range s.Trail {
				r.out = append(r.out, agent.Line{Kind: agent.Activity, Text: t})
			}
			m.focusRight = true
			m.refreshPane()
			m.vp.GotoTop()
			return m, nil
		}
	}

	if !agent.Available() {
		r.err = "claude CLI not found on PATH"
		m.refreshPane()
		return m, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := agent.Run(ctx, u, m.notes[u.Name], m.updates)

	r.cancel = cancel
	r.ch = ch
	r.running = true
	r.start = time.Now()
	m.focusRight = true
	m.refreshPane()
	m.vp.GotoTop()
	return m, tea.Batch(waitAgent(u.Name, ch), m.sp.Tick)
}

// saveAnalysis stores a finished run so reopening it is free.
//
// Takes the name rather than reading the selection, because the run that just
// finished is usually not the one on screen any more.
func (m *Model) saveAnalysis(name string) {
	r := m.runs[name]
	if r == nil || strings.TrimSpace(r.text) == "" {
		return
	}
	var u model.Update
	found := false
	for _, c := range m.updates {
		if c.Name == name {
			u, found = c, true
			break
		}
	}
	if !found {
		return
	}
	s := agent.Stored{Text: r.text}
	for _, l := range r.out {
		if l.Kind == agent.Activity {
			s.Trail = append(s.Trail, l.Text)
		}
	}
	agent.SaveStored(u, s)
}

// ── rendering ──────────────────────────────────────────────────────────────

func badge(u model.Update) string {
	switch {
	case agent.IsSystem(u):
		return stBlue.Render("⟳")
	case len(u.CVEs) > 0, u.UpstreamCVEs > 0:
		return stRed.Render("●")
	case u.MaintainerWas != "":
		return stYellow.Render("▲")
	case u.UpstreamKind == model.KindSuspected:
		return stYellow.Render("◍")
	case u.OutOfDate:
		return stYellow.Render("○")
	case u.Origin == model.AUR:
		return stMauve.Render("·")
	}
	return stDim.Render("·")
}

// note is the one-line reason a row is flagged, shown under the version delta
// so the list answers "why" without needing the right pane.
func note(u model.Update) string {
	switch {
	case agent.IsSystem(u):
		return "everything, right now"
	case len(u.CVEs) > 0:
		return fmt.Sprintf("%s · %d CVEs", u.Severity, len(u.CVEs))
	case u.MaintainerWas != "":
		return "maintainer changed"
	case u.UpstreamCVEs > 0:
		return fmt.Sprintf("%d CVEs upstream", u.UpstreamCVEs)
	case u.UpstreamKind == model.KindSuspected:
		return "possibly security-relevant"
	case u.OutOfDate:
		return "flagged out-of-date"
	}
	return ""
}

func (m Model) renderList(w int) string {
	if m.booting {
		// Kept short deliberately: this pane is around 28 columns and a longer
		// message wraps into the row grid below it.
		return m.sp.View() + stDim.Render(" scanning…")
	}
	// Counted rather than testing the slice for emptiness: m.updates always
	// holds the synthetic whole-system row, so the length is never zero and
	// this message was unreachable. A machine with nothing pending showed a
	// bare system row and no word that it was up to date.
	if pending, _ := counts(m.updates); pending == 0 {
		return stGreen.Render("✓ everything is up to date")
	}

	// Each entry occupies two lines (name, then version and reason), so the
	// number of entries that fit is half the available height.
	vis := (m.h - 4) / rowLines
	if vis < 1 {
		vis = 1
	}
	// The window is derived from the cursor on every frame rather than being
	// carried as state. View has a value receiver and could not write it back
	// anyway, and deriving it means the list can never scroll out of sync with
	// the selection.
	top := 0
	if m.cursor >= vis {
		top = m.cursor - vis + 1
	}

	// The pane's own right border and padding each consume a cell, so the text
	// budget is narrower than the width the caller asked for. Overrunning it
	// wraps every second row and desynchronises the two-line layout.
	avail := w - 2
	if avail < 10 {
		avail = 10
	}

	var b strings.Builder
	rows := m.visible()
	for i := top; i < len(rows) && i < top+vis; i++ {
		u := rows[i]
		// A running analysis takes over the badge. With several in flight the
		// title says how many but not which, and the badge is the only place
		// the list can answer that without a third line per row.
		mark := badge(u)
		if r := m.runs[u.Name]; r != nil && r.running {
			mark = m.sp.View()
		}
		// Prefix is two cells of cursor plus badge and a space.
		line := "  " + mark + " " + truncate(u.Name, avail-4)
		if i == m.cursor {
			line = stSel.Render("❯ ") + mark + " " +
				stSel.Render(truncate(u.Name, avail-4))
		}
		b.WriteString(line + "\n")

		// The synthetic row has no version pair worth showing — its "versions"
		// are a package count and a digest of the transaction.
		sub := fmt.Sprintf("    %s → %s", u.Cur, u.New)
		if agent.IsSystem(u) {
			sub = "    " + u.Cur
		}
		if n := note(u); n != "" {
			sub += "  " + n
		}
		// Truncate before styling: cutting a rendered string would slice
		// through an ANSI escape and leak the terminal's colour state into
		// every line below it.
		b.WriteString(stDim.Render(truncate(sub, avail)) + "\n")
	}
	return b.String()
}

// sevSummary is the one-line severity distribution across every release in
// range. Segments are dropped from the tail rather than the whole line being
// truncated, because a half-written "184 Medium ·" reads as a rendering fault
// and the leading counts are the ones that matter.
func sevSummary(rels []model.Release, w int) string {
	counts := map[string]int{}
	seen := map[string]bool{}
	total := 0
	for _, r := range rels {
		for _, c := range r.CVEs {
			if seen[c] {
				continue
			}
			seen[c] = true
			total++
			if s, ok := r.Severities[c]; ok {
				counts[s]++
			}
		}
	}
	if total == 0 {
		return ""
	}

	type seg struct {
		text string
		st   lipgloss.Style
	}
	segs := []seg{{fmt.Sprintf("%d CVEs", total), stBold}}
	for _, s := range model.Severities {
		if counts[s] == 0 {
			continue
		}
		st := stDim
		switch s {
		case "Critical":
			st = stRed
		case "High":
			st = stYellow
		}
		segs = append(segs, seg{fmt.Sprintf("%d %s", counts[s], s), st})
	}

	var out []string
	used := 0
	for i, s := range segs {
		add := len(s.text)
		if i > 0 {
			add += 3 // " · "
		}
		if used+add > w {
			break
		}
		used += add
		out = append(out, s.st.Render(s.text))
	}
	return strings.Join(out, stDim.Render(" · "))
}

func kindLabel(k model.Kind) string {
	switch k {
	case model.KindSecurity:
		return stRed.Render("security")
	case model.KindSuspected:
		return stYellow.Render("possibly security-relevant")
	case model.KindChangelog:
		return stBlue.Render("changelog")
	}
	return stDim.Render("no changelog source")
}

func (m Model) renderNotes() string {
	u, ok := m.sel()
	if !ok {
		if m.booting {
			return ""
		}
		return stDim.Render("nothing selected")
	}

	if agent.IsSystem(u) {
		return m.renderSystem()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", stBold.Render(u.Name),
		stDim.Render(string(u.Origin)))
	fmt.Fprintf(&b, "%s\n\n", stDim.Render(u.Cur+"  →  "+u.New))

	if u.MaintainerWas != "" {
		fmt.Fprintf(&b, "%s maintainer changed: %s → %s\n",
			stYellow.Render("▲"), u.MaintainerWas, u.Maintainer)
		fmt.Fprintf(&b, "%s\n\n", stDim.Render(
			"  review the PKGBUILD before building — this is the AUR adoption vector"))
	}
	if u.OutOfDate {
		fmt.Fprintf(&b, "%s community-flagged out-of-date\n\n", stYellow.Render("○"))
	}
	if len(u.CVEs) > 0 {
		fmt.Fprintf(&b, "%s Arch Security Tracker · %s\n", stRed.Render("●"), u.Severity)
		fmt.Fprintf(&b, "%s\n\n", stDim.Render("  "+wrapJoin(u.CVEs, 6, m.vp.Width-4)))
	}

	n, have := m.notes[u.Name]
	if !have {
		if m.loading[u.Name] {
			return b.String() + m.sp.View() + stDim.Render(" reading upstream release notes…")
		}
		return b.String() + stDim.Render("press r to load release notes")
	}

	fmt.Fprintf(&b, "%s  %s\n", stDim.Render(truncate(n.Source, m.vp.Width-14)),
		kindLabel(n.Kind))
	if s := sevSummary(n.Releases, m.vp.Width-1); s != "" {
		fmt.Fprintf(&b, "%s\n", s)
	}
	b.WriteString("\n")

	if len(n.Releases) == 0 {
		msg := n.Reason()
		// Stated plainly rather than left blank. "No signal exists" and "all
		// clear" are different answers, and only one of them is honest here.
		fmt.Fprintf(&b, "%s\n", stDim.Render(msg))
		if u.URL != "" {
			fmt.Fprintf(&b, "%s\n", stDim.Render(u.URL))
		}
		fmt.Fprintf(&b, "\n%s\n", stDim.Render(
			"press a to send an agent to read the source diff directly"))
		return b.String()
	}

	for _, r := range n.Releases {
		head := fmt.Sprintf("▌ %s", r.Version)
		if r.Date != "" {
			head += "   " + r.Date
		}
		fmt.Fprintf(&b, "%s\n", stMauve.Render(head))
		if len(r.CVEs) > 0 {
			fmt.Fprintf(&b, "  %s\n", stRed.Render(wrapJoin(r.CVEs, 5, m.vp.Width-4)))
		}
		body := strings.TrimSpace(r.Body)
		if body != "" {
			for _, line := range strings.Split(body, "\n") {
				fmt.Fprintf(&b, "  %s\n", truncate(line, m.vp.Width-4))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// verdictBanner is the headline answer, styled by how much it demands.
func verdictBanner(v render.Verdict, w int) string {
	st := stGreenBold
	switch render.Urgency(v) {
	case 2:
		st = stRedBold
	case 1:
		st = stYellowBold
	}
	label := "  " + string(v) + "  "
	if len(label) > w {
		label = truncate(label, w)
	}
	return st.Render(label)
}

// renderSystem is the pane for the whole-transaction row before it is analysed.
//
// Shows what can be known without spending anything: the shape of the
// transaction, and any Arch announcement demanding a manual step. That last
// one is worth surfacing here rather than only inside an analysis, because
// skipping it is how an ordinary upgrade turns into a broken system, and it
// costs one cached feed fetch to check.
func (m Model) renderSystem() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", stBold.Render("Full system upgrade"))
	fmt.Fprintf(&b, "%s\n\n", stDim.Render(truncate(upgradeLabel(), m.vp.Width)))

	var repo, aur, fp, sn, flagged int
	for _, u := range m.updates {
		if agent.IsSystem(u) {
			continue
		}
		switch u.Origin {
		case model.AUR:
			aur++
		case model.Flatpak:
			fp++
		case model.Snap:
			sn++
		default:
			repo++
		}
		if u.Flagged() {
			flagged++
		}
	}
	// Counts of zero for a category this machine does not have are noise, so
	// each is shown only when it applies. Repository packages always are.
	fmt.Fprintf(&b, "%d repository", repo)
	if aur > 0 {
		fmt.Fprintf(&b, " · %d AUR", aur)
	}
	if fp > 0 {
		fmt.Fprintf(&b, " · %d flatpak", fp)
	}
	if sn > 0 {
		fmt.Fprintf(&b, " · %d snap", sn)
	}
	if flagged > 0 {
		fmt.Fprintf(&b, " · %s", stRed.Render(fmt.Sprintf("%d flagged", flagged)))
	}
	b.WriteString("\n\n")

	// Named explicitly so the claim "full system upgrade" can be checked
	// rather than taken on trust. Which managers appear here is detected at
	// runtime, so this is the machine's real answer and not an assumption.
	fmt.Fprintf(&b, "%s\n", stBold.Render("Managers it will drive"))
	for _, mg := range sources.Managers() {
		suffix := ""
		if mg.List == nil {
			suffix = stDim.Render("  (not itemised)")
		}
		fmt.Fprintf(&b, "  %s%s\n", truncate(mg.Name, m.vp.Width-6), suffix)
	}
	if un := sources.Unmanaged(); len(un) > 0 {
		fmt.Fprintf(&b, "\n%s\n", stDim.Render("Not covered by any of them:"))
		for _, u := range un {
			head, _, _ := strings.Cut(u, " —")
			fmt.Fprintf(&b, "%s\n", stDim.Render(truncate("  · "+head, m.vp.Width)))
		}
	}
	b.WriteString("\n")

	news := sources.News(6)
	var urgent []sources.NewsItem
	for _, it := range news {
		if it.RequiresIntervention() {
			urgent = append(urgent, it)
		}
	}
	if len(urgent) > 0 {
		fmt.Fprintf(&b, "%s\n", stYellow.Render(truncate("⚠ Arch news announcing manual steps", m.vp.Width)))
		for _, it := range urgent {
			fmt.Fprintf(&b, "  %s\n", truncate(it.Title, m.vp.Width-4))
			fmt.Fprintf(&b, "  %s\n", stDim.Render(truncate(it.Link, m.vp.Width-4)))
		}
		fmt.Fprintf(&b, "%s\n\n", stDim.Render(truncate(
			"  These may or may not apply here — the analysis checks.", m.vp.Width)))
	} else if len(news) > 0 {
		fmt.Fprintf(&b, "%s\n\n", stGreen.Render(truncate(
			"✓ no Arch news announcing manual intervention", m.vp.Width)))
	}

	w := m.vp.Width
	fmt.Fprintf(&b, "%s\n", stDim.Render(truncate(
		"press a to assess what this upgrade would actually do:", w)))
	// The middle two lines name what this host's analysis actually covers.
	// Promising an AUR rebuild list on a machine with no AUR advertises a
	// section the report will not contain.
	rebuild := "what the upgrade does not rebuild for you"
	config := "reboots, config files left to merge, and recovery if it goes wrong"
	if sources.Host().Family == sources.Arch {
		rebuild = "which AUR packages need rebuilding by hand"
		config = "reboots, .pacnew files, and recovery if it goes wrong"
	}
	for _, l := range []string{
		"what breaks, and what to do about it",
		rebuild,
		"whether any announcement applies here",
		config,
	} {
		fmt.Fprintf(&b, "%s\n", stDim.Render(truncate("  · "+l, w)))
	}
	return b.String()
}

func (m Model) renderAgent() string {
	var b strings.Builder
	u, ok := m.sel()
	r := m.run()
	if !ok || r == nil {
		return stDim.Render("no analysis for this package")
	}

	fmt.Fprintf(&b, "%s %s", stMauve.Render("agent ·"), stBold.Render(u.Name))
	if r.fromCache {
		fmt.Fprintf(&b, "  %s", stDim.Render("(stored — A to re-run)"))
	}
	// What else is in flight, so leaving a run to check another does not mean
	// losing track of it.
	if n := m.runningCount(); n > 0 && !(n == 1 && r.running) {
		fmt.Fprintf(&b, "  %s", stDim.Render(fmt.Sprintf("(%d running)", n)))
	}
	b.WriteString("\n")

	if r.running {
		// Elapsed seconds alongside the spinner. A spinner only proves the
		// interface is repainting; a climbing clock proves the run itself is
		// still going, which is the question during a two-minute silence.
		el := time.Since(r.start).Round(time.Second)
		fmt.Fprintf(&b, "%s\n", m.sp.View()+stDim.Render(fmt.Sprintf(
			" reading the source diff · %s · %d steps · x to cancel",
			el, len(r.out))))
	}
	if r.err != "" {
		fmt.Fprintf(&b, "%s %s\n", stRed.Render("error:"), r.err)
	}
	b.WriteString("\n")

	if r.text == "" && len(r.out) == 0 && !r.running && r.err == "" {
		return b.String() + stDim.Render("no output")
	}

	// While the run is live the tool trail is the only sign of progress, so it
	// leads. Once the analysis has landed the trail becomes evidence rather
	// than news, and the document takes the top.
	trail := func() {
		for _, l := range r.out {
			if l.Kind != agent.Activity {
				continue
			}
			b.WriteString(stDim.Render("  → "+truncate(l.Text, m.vp.Width-4)) + "\n")
		}
	}

	if r.running || r.text == "" {
		trail()
		if r.text != "" {
			b.WriteString("\n" + render.Markdown(render.Document(r.text), m.vp.Width))
		}
		return b.String()
	}

	b.WriteString(render.Markdown(render.Document(r.text), m.vp.Width))
	if len(r.out) > 0 {
		b.WriteString("\n\n" + stDim.Render("  ── what it read ──") + "\n")
		trail()
	}
	return b.String()
}

func counts(ups []model.Update) (pending, flagged int) {
	for _, u := range ups {
		if agent.IsSystem(u) {
			continue
		}
		pending++
		if u.Flagged() {
			flagged++
		}
	}
	return pending, flagged
}

// tabLabel names one tab: the reporting manager where that is unambiguous, the
// origin otherwise.
//
// Origin is the wrong label on its own. Ubuntu files every apt package under
// "repo", an Arch distinction between the official repositories and the AUR
// that has no meaning where there is no AUR. The manager name is wrong on its
// own too: one registry entry reports both halves of an Arch system, so
// labelling by it would put "pacman + AUR" on two tabs and hide the split that
// decides what a system upgrade rebuilds.
//
// Read from the registry rather than from the pending rows. Inferring it from
// what is pending made the label flip: an Arch machine with no AUR updates
// outstanding showed one manager covering the only origin present, and its
// repository tab renamed itself to "pacman + AUR" until an AUR package fell
// behind.
func tabLabel(ms []sources.Manager, o model.Origin) string {
	name := ""
	for _, m := range ms {
		if m.Origin != o {
			continue
		}
		if name != "" {
			return originName(o) // two managers feed it; neither names it
		}
		name = m.Name
	}
	if name == "" {
		return originName(o)
	}
	return name
}

// originName is the fallback label when no single registry entry claims an
// origin.
//
// Repository packages take the family's manager: pacman here, apt on Debian.
// The Arch entry reports repository and AUR packages together, so it cannot
// lend its name to either tab, and "repo" told an Arch user nothing they did
// not already know while telling an Ubuntu user something untrue.
func originName(o model.Origin) string {
	if o == model.Repo {
		if n := sources.Host().RepoManager; n != "" {
			return n
		}
	}
	return string(o)
}

// renderTabs is the manager tab bar: the combined view first, then one tab
// per origin that actually has pending rows.
func (m Model) renderTabs() string {
	if len(m.tabOrigins) == 0 {
		return ""
	}
	label := func(i int, text string, n int) string {
		t := fmt.Sprintf(" %s %d ", text, n)
		if i == m.tab {
			return stBold.Render(stMauve.Render(t))
		}
		return stDim.Render(t)
	}
	perOrigin := map[model.Origin]int{}
	total := 0
	for _, u := range m.updates {
		if agent.IsSystem(u) {
			continue
		}
		perOrigin[u.Origin]++
		total++
	}
	ms := sources.Managers()
	parts := []string{label(0, "all", total)}
	for i, o := range m.tabOrigins {
		parts = append(parts, label(i+1, tabLabel(ms, o), perOrigin[o]))
	}
	return strings.Join(parts, stDim.Render("·"))
}

func (m Model) View() string {
	if m.w == 0 {
		return "starting…"
	}

	pending, flagged := counts(m.updates)
	title := stTitle.Render("system-patch")
	sub := stDim.Render(fmt.Sprintf(" %d updates", pending))
	if flagged > 0 {
		sub += stRed.Render(fmt.Sprintf(" · %d flagged", flagged))
	}
	// Analyses run concurrently, so the count is the only place that says how
	// many are still going once you have moved off them.
	if n := m.runningCount(); n > 0 {
		sub += stMauve.Render(fmt.Sprintf(" · %d analysing", n))
	}
	if m.upgradeErr != "" {
		sub += stRed.Render(" · " + m.upgradeErr)
	}
	for _, w := range m.warnings {
		sub += stYellow.Render(" · " + w)
	}

	lw := m.leftWidth()
	left := stLeft.Width(lw).Render(m.renderList(lw))
	right := ""
	if m.ready {
		right = m.vp.View()
		if pin := m.pinnedVerdict(); pin != "" {
			right = pin + "\n" + right
		}
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)

	keys := "↑↓ move · ←→ manager · a analyse · i install · r reload · R rescan · q quit"
	if r := m.run(); m.mode == paneAgent && r != nil && r.running {
		keys = "x cancel · tab scroll · esc back · q quit"
	} else if m.focusRight {
		keys = "scrolling right pane · tab back · esc list · q quit"
	}

	if m.confirming {
		// Names exactly what y will run. When the plan is wider than the
		// selection — a repo package, where no safe single-package path
		// exists — it says so and why, rather than letting "install this one"
		// silently become "upgrade everything".
		note := "y / n"
		if m.plan.why != "" {
			note = m.plan.why + " — y / n"
		} else if m.plan.full {
			note = "every manager, everything pending — y / n"
		}
		keys = stYellow.Render("run `"+m.plan.label+"`? ") + stDim.Render(note)
	}

	head := title + sub
	if tabs := m.renderTabs(); tabs != "" {
		head += "\n" + tabs
	}
	return fmt.Sprintf("%s\n%s\n\n%s", head, body, stDim.Render(keys))
}

// ── helpers ────────────────────────────────────────────────────────────────

// wrapJoin renders at most n items followed by a count of the remainder, so a
// package carrying 300 CVEs does not push everything else off the pane.
//
// The remainder count is part of the string before truncation, not appended
// after it, or the result overruns the width it was given. The slice is never
// sorted in place: sources orders CVEs with the highest-severity advisory's
// first, and a render pass has no business rearranging that.
func wrapJoin(items []string, n, w int) string {
	return truncate(render.CapList(items, n), w)
}

// Run starts the program.
func Run() error {
	p := tea.NewProgram(New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// truncate and wrapJoin delegate to render, which owns the shared text
// helpers. Kept as local names so the call sites read the same.
func truncate(s string, n int) string { return render.Truncate(s, n) }
