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

	"github.com/Sousf/patchlens/internal/adapters"
	"github.com/Sousf/patchlens/internal/agent"
	"github.com/Sousf/patchlens/internal/model"
	"github.com/Sousf/patchlens/internal/render"
	"github.com/Sousf/patchlens/internal/sources"
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
type agentMsg agent.Line

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

	mode         pane
	focusRight   bool
	agentFor     string
	agentOut     []agent.Line
	agentRunning bool
	agentErr     string
	agentCh      <-chan agent.Line
	agentCancel  context.CancelFunc

	// Markdown accumulated from the agent's prose, kept separate from the
	// activity trail so it can be rendered as one document.
	agentText string
	// Verdicts by package name, so the list can show what a previous
	// analysis concluded without reopening it.
	verdicts map[string]render.Verdict
	// True when the pane is showing a stored analysis rather than a live run.
	fromCache bool

	// Tab state: 0 is the combined view, i>0 selects tabOrigins[i-1]. The
	// cursor indexes the visible (filtered) list, not m.updates.
	tab        int
	tabOrigins []model.Origin

	// Set while the upgrade confirmation is on screen.
	confirming bool
	// When the running analysis started, for the elapsed-time readout.
	agentStart time.Time
}

// upgradeSteps is every manager the upgrade has to drive, in order.
//
// It is a FULL upgrade, and single-package install is deliberately not
// offered. `pacman -S one-package` resolves against the synced database and
// pulls in libraries built for packages you have not upgraded yet — the
// partial-upgrade breakage Arch warns about, and the most common way to end up
// with a system that will not boot. There is no safe single-package path, so
// the honest options are a full upgrade or nothing.
//
// The set is detected rather than hardcoded, so "full system upgrade" means
// every manager actually installed here and not just the one Arch ships.
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

type upgradeDoneMsg struct{ err error }

// runUpgrade hands the terminal to the package manager.
//
// tea.ExecProcess suspends the interface for the duration: the upgrade needs a
// real terminal for the sudo password and for pacman's own conflict and
// replacement prompts. Answering those blind through a captured pipe is how
// people confirm things they did not read.
func runUpgrade() tea.Cmd {
	argv := upgradeCmd()
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
		notes:    map[string]model.Notes{},
		loading:  map[string]bool{},
		verdicts: map[string]render.Verdict{},
		sp:       sp,
		booting:  true,
		w:        80,
		h:        24,
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

func fetchNotes(u model.Update, refresh bool) tea.Cmd {
	return func() tea.Msg {
		return notesMsg{name: u.Name, notes: adapters.For(u, refresh)}
	}
}

// waitAgent pumps one line off the agent's channel per Cmd, re-arming itself
// until the channel closes. This is how a streaming subprocess is folded into
// bubbletea's single-threaded update loop without blocking it.
func waitAgent(ch <-chan agent.Line) tea.Cmd {
	return func() tea.Msg {
		l, ok := <-ch
		if !ok {
			return agentMsg{Done: true}
		}
		return agentMsg(l)
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
	vh := m.h - 4
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
		if m.booting || m.agentRunning || len(m.loading) > 0 {
			var c tea.Cmd
			m.sp, c = m.sp.Update(msg)
			cmds = append(cmds, c)

			// The spinner is drawn inside the viewport's content, and a
			// viewport only redraws what it was last given. Advancing the
			// spinner without re-rendering the pane left a frozen frame on
			// screen through every gap between tool calls — precisely the
			// stretches where the agent is thinking and the reader most needs
			// to see it is still alive.
			if m.agentRunning && m.mode == paneAgent {
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
		if msg.Kind == agent.Text {
			// Blank text lines are kept: they are the paragraph breaks that
			// make the Markdown parse as separate blocks.
			m.agentText += msg.Text + "\n"
		} else if msg.Text != "" {
			m.agentOut = append(m.agentOut, agent.Line(msg))
		}
		if msg.Done {
			m.agentRunning = false
			m.agentCh = nil
			if msg.Err != nil && msg.Err != context.Canceled {
				m.agentErr = msg.Err.Error()
			}
			m.saveAnalysis()
		} else if m.agentCh != nil {
			cmds = append(cmds, waitAgent(m.agentCh))
		}
		if m.mode == paneAgent {
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
		m.agentErr = ""
		if msg.err != nil {
			m.agentErr = "upgrade: " + msg.err.Error()
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
			return m, runUpgrade()
		default:
			m.confirming = false
			return m, nil
		}
	}

	switch msg.String() {
	case "q", "ctrl+c":
		if m.agentCancel != nil {
			m.agentCancel()
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
			m.mode = paneNotes
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
			m.mode = paneNotes
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
			m.mode = paneNotes
			if cmd := m.ensureNotes(); cmd != nil {
				cmds = append(cmds, cmd)
			}
			m.refreshPane()
		}
		return m, tea.Batch(cmds...)

	case "G":
		if !m.focusRight && len(m.visible()) > 0 {
			m.cursor = len(m.visible()) - 1
			m.mode = paneNotes
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
		if m.agentRunning {
			return m, nil
		}
		m.confirming = true
		return m, nil

	case "x":
		if m.agentRunning && m.agentCancel != nil {
			m.agentCancel()
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
	if m.agentRunning {
		// Refuse rather than queue: two analyses interleaving into one output
		// pane would be unreadable, and the running one is usually the one
		// wanted.
		return m, nil
	}

	m.mode = paneAgent
	m.agentFor = u.Name
	m.agentErr = ""
	m.agentOut = nil
	m.agentText = ""
	m.fromCache = false

	// A stored analysis for these exact versions is shown rather than
	// re-derived. The run costs real money and the answer cannot have changed
	// while both version numbers stayed the same.
	if !force {
		if s, hit := agent.LoadStored(u); hit {
			m.agentText = s.Text
			m.fromCache = true
			for _, t := range s.Trail {
				m.agentOut = append(m.agentOut, agent.Line{Kind: agent.Activity, Text: t})
			}
			if v, okv := render.FindVerdict(s.Text); okv {
				m.verdicts[u.Name] = v
			}
			m.focusRight = true
			m.refreshPane()
			m.vp.GotoTop()
			return m, nil
		}
	}

	if !agent.Available() {
		m.agentErr = "claude CLI not found on PATH"
		m.refreshPane()
		return m, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := agent.Run(ctx, u, m.notes[u.Name], m.updates)

	m.agentCancel = cancel
	m.agentCh = ch
	m.agentRunning = true
	m.agentStart = time.Now()
	m.focusRight = true
	m.refreshPane()
	m.vp.GotoTop()
	return m, tea.Batch(waitAgent(ch), m.sp.Tick)
}

// saveAnalysis stores a finished run so reopening it is free.
func (m *Model) saveAnalysis() {
	u, ok := m.sel()
	if !ok || u.Name != m.agentFor || strings.TrimSpace(m.agentText) == "" {
		return
	}
	s := agent.Stored{Text: m.agentText}
	if v, okv := render.FindVerdict(m.agentText); okv {
		m.verdicts[u.Name] = v
	}
	for _, l := range m.agentOut {
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
	if len(m.updates) == 0 {
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
		// Prefix is two cells of cursor plus badge and a space.
		line := "  " + badge(u) + " " + truncate(u.Name, avail-4)
		if i == m.cursor {
			line = stSel.Render("❯ ") + badge(u) + " " +
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
	for _, s := range []string{"Critical", "High", "Medium", "Low"} {
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
		msg := n.Err
		if msg == "" {
			msg = "upstream publishes no release notes"
		}
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
	st := stGreen
	switch render.Urgency(v) {
	case 2:
		st = lipgloss.NewStyle().Bold(true).Foreground(cRed)
	case 1:
		st = lipgloss.NewStyle().Bold(true).Foreground(cYellow)
	default:
		st = lipgloss.NewStyle().Bold(true).Foreground(cGreen)
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

	var repo, aur, fp, flagged int
	for _, u := range m.updates {
		if agent.IsSystem(u) {
			continue
		}
		switch u.Origin {
		case model.AUR:
			aur++
		case model.Flatpak:
			fp++
		default:
			repo++
		}
		if u.Flagged() {
			flagged++
		}
	}
	fmt.Fprintf(&b, "%d repository · %d AUR · %d flatpak", repo, aur, fp)
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
	for _, l := range []string{
		"what breaks, and what to do about it",
		"which AUR packages need rebuilding by hand",
		"whether any announcement applies here",
		"reboots, .pacnew files, and recovery if it goes wrong",
	} {
		fmt.Fprintf(&b, "%s\n", stDim.Render(truncate("  · "+l, w)))
	}
	return b.String()
}

func (m Model) renderAgent() string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s", stMauve.Render("agent ·"), stBold.Render(m.agentFor))
	if m.fromCache {
		fmt.Fprintf(&b, "  %s", stDim.Render("(stored — A to re-run)"))
	}
	b.WriteString("\n")

	// The verdict leads. It is the one line worth reading if you read nothing
	// else, so it sits above the document rather than at the end of it, and it
	// appears the moment the agent commits to it mid-stream.
	if v, ok := render.FindVerdict(m.agentText); ok {
		b.WriteString(verdictBanner(v, m.vp.Width) + "\n")
		if render.Urgency(v) > 0 {
			b.WriteString(stDim.Render("  i to upgrade the system") + "\n")
		}
	}

	if m.agentRunning {
		// Elapsed seconds alongside the spinner. A spinner only proves the
		// interface is repainting; a climbing clock proves the run itself is
		// still going, which is the question during a two-minute silence.
		el := time.Since(m.agentStart).Round(time.Second)
		fmt.Fprintf(&b, "%s\n", m.sp.View()+stDim.Render(fmt.Sprintf(
			" reading the source diff · %s · %d steps · x to cancel",
			el, len(m.agentOut))))
	}
	if m.agentErr != "" {
		fmt.Fprintf(&b, "%s %s\n", stRed.Render("error:"), m.agentErr)
	}
	b.WriteString("\n")

	if m.agentText == "" && len(m.agentOut) == 0 && !m.agentRunning && m.agentErr == "" {
		return b.String() + stDim.Render("no output")
	}

	// While the run is live the tool trail is the only sign of progress, so it
	// leads. Once the analysis has landed the trail becomes evidence rather
	// than news, and the document takes the top.
	trail := func() {
		for _, l := range m.agentOut {
			if l.Kind != agent.Activity {
				continue
			}
			b.WriteString(stDim.Render("  → "+truncate(l.Text, m.vp.Width-4)) + "\n")
		}
	}

	if m.agentRunning || m.agentText == "" {
		trail()
		if m.agentText != "" {
			b.WriteString("\n" + render.Markdown(render.Document(m.agentText), m.vp.Width))
		}
		return b.String()
	}

	b.WriteString(render.Markdown(render.Document(m.agentText), m.vp.Width))
	if len(m.agentOut) > 0 {
		b.WriteString("\n\n" + stDim.Render("  ── what it read ──") + "\n")
		trail()
	}
	return b.String()
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
	counts := map[model.Origin]int{}
	total := 0
	for _, u := range m.updates {
		if agent.IsSystem(u) {
			continue
		}
		counts[u.Origin]++
		total++
	}
	parts := []string{label(0, "all", total)}
	for i, o := range m.tabOrigins {
		parts = append(parts, label(i+1, string(o), counts[o]))
	}
	return strings.Join(parts, stDim.Render("·"))
}

func (m Model) View() string {
	if m.w == 0 {
		return "starting…"
	}

	flagged := 0
	for _, u := range m.updates {
		if u.Flagged() {
			flagged++
		}
	}
	title := stTitle.Render("patchlens")
	sub := stDim.Render(fmt.Sprintf(" %d updates", len(m.updates)))
	if flagged > 0 {
		sub += stRed.Render(fmt.Sprintf(" · %d flagged", flagged))
	}
	for _, w := range m.warnings {
		sub += stYellow.Render(" · " + w)
	}

	lw := m.leftWidth()
	left := stLeft.Width(lw).Render(m.renderList(lw))
	right := ""
	if m.ready {
		right = m.vp.View()
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)

	keys := "↑↓ move · ←→ manager · a analyse · i upgrade · r reload · R rescan · q quit"
	if m.mode == paneAgent && m.agentRunning {
		keys = "x cancel · tab scroll · esc back · q quit"
	} else if m.focusRight {
		keys = "scrolling right pane · tab back · esc list · q quit"
	}

	if m.confirming {
		argv := upgradeLabel()
		// Names the exact command and says plainly that it is system-wide.
		// "Install this package" is what was asked for and is not a thing Arch
		// can safely do; being vague here would let that misunderstanding
		// survive right up until something breaks.
		keys = stYellow.Render("run `"+argv+"`? ") +
			stDim.Render("full system upgrade, not just this package — y / n")
	}

	return fmt.Sprintf("%s%s\n%s\n%s\n\n%s",
		title, sub, m.renderTabs(), body, stDim.Render(keys))
}

// ── helpers ────────────────────────────────────────────────────────────────

func truncate(s string, w int) string {
	if w < 4 {
		w = 4
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	return string(r[:w-1]) + "…"
}

// wrapJoin renders at most n items followed by a count of the remainder, so a
// package carrying 300 CVEs does not push everything else off the pane.
//
// The remainder count is part of the string before truncation, not appended
// after it, or the result overruns the width it was given. The slice is never
// sorted in place: sources orders CVEs with the highest-severity advisory's
// first, and a render pass has no business rearranging that.
func wrapJoin(items []string, n, w int) string {
	if len(items) <= n {
		return truncate(strings.Join(items, ", "), w)
	}
	s := fmt.Sprintf("%s … +%d more",
		strings.Join(items[:n], ", "), len(items)-n)
	return truncate(s, w)
}

// Run starts the program.
func Run() error {
	p := tea.NewProgram(New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
