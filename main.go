// Command patchlens shows every pending package update, explains why each one
// was pushed, and can send an agent to read the source diff and judge whether
// it is worth installing.
//
// Run with no arguments for the interactive interface. The subcommands exist
// so the same data can drive a status bar or a notification without a TTY.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Sousf/patchlens/internal/adapters"
	"github.com/Sousf/patchlens/internal/agent"
	"github.com/Sousf/patchlens/internal/cache"
	"github.com/Sousf/patchlens/internal/model"
	"github.com/Sousf/patchlens/internal/render"
	"github.com/Sousf/patchlens/internal/sources"
	"github.com/Sousf/patchlens/internal/ui"
)

// cacheTTL bounds how stale a non-interactive answer may be. Short enough that
// a bar badge tracks reality, long enough that polling it every thirty seconds
// does not re-sync the package database each time. Installing or removing
// anything invalidates the cache regardless of age.
const cacheTTL = 10 * time.Minute

const usage = `patchlens — what is pending, why it was pushed, and whether to take it

  patchlens              interactive two-pane browser
  patchlens list         one line per pending update
  patchlens json         the same data as JSON, for scripts and bar modules
  patchlens count        number of flagged updates, for a status badge
  patchlens notes <pkg>  release notes for one package, plain text
  patchlens analyse <pkg>  send an agent to read the source diff and judge it
  patchlens analyse system   assess upgrading everything, right now
  patchlens prompt <pkg>   print that agent's brief without running it

Keys inside the interface:
  ↑/↓ or j/k   move            a      analyse the source (A re-runs, ignoring
  enter/tab    focus the pane         the stored answer)
  r            reload notes    i      upgrade the system, after confirming
  R            rescan          x      cancel a running agent
  q            quit
`

func main() {
	// Reap cache entries no reader can serve and scratch directories orphaned
	// by killed runs. In the background: it is pure hygiene, and startup —
	// especially `patchlens count` from a status bar — must not wait on it.
	go cache.Sweep()

	args := os.Args[1:]
	if len(args) == 0 {
		if err := ui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "patchlens:", err)
			os.Exit(1)
		}
		return
	}

	switch args[0] {
	case "list":
		os.Exit(cmdList())
	case "json":
		os.Exit(cmdJSON())
	case "count":
		os.Exit(cmdCount())
	case "notes":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "patchlens notes: need a package name")
			os.Exit(2)
		}
		os.Exit(cmdNotes(args[1]))
	case "analyse", "analyze":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "patchlens analyse: need a package name")
			os.Exit(2)
		}
		os.Exit(cmdAnalyse(args[1], false))
	case "prompt":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "patchlens prompt: need a package name")
			os.Exit(2)
		}
		os.Exit(cmdAnalyse(args[1], true))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "patchlens: unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}
}

func cmdList() int {
	res := sources.Load(cacheTTL)
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	for _, u := range res.Updates {
		mark, why := " ", ""
		switch {
		case len(u.CVEs) > 0:
			mark = "!"
			why = fmt.Sprintf("%s, %d CVEs (tracker)", u.Severity, len(u.CVEs))
		case u.MaintainerWas != "":
			mark = "^"
			why = "maintainer " + u.MaintainerWas + " -> " + u.Maintainer
		case u.UpstreamCVEs > 0:
			mark = "!"
			why = fmt.Sprintf("%d CVEs (upstream)", u.UpstreamCVEs)
		case u.OutOfDate:
			mark = "?"
			why = "flagged out-of-date"
		}
		fmt.Printf("%s %-32s %-22s -> %-22s %-5s %s\n",
			mark, u.Name, u.Cur, u.New, u.Origin, why)
	}
	return 0
}

// find locates one pending update by name, also returning the whole set — the
// whole-system analysis needs every row, not just the selected one.
//
// "system" is not a package. It selects the synthetic whole-transaction entry,
// answering "is it safe to upgrade everything right now" rather than anything
// about one package.
func find(name string) (model.Update, []model.Update, bool) {
	res := sources.Load(cacheTTL)
	if name == "system" {
		return agent.SystemEntry(res.Updates), res.Updates, true
	}
	for _, u := range res.Updates {
		if u.Name == name {
			return u, res.Updates, true
		}
	}
	return model.Update{}, res.Updates, false
}

// cmdAnalyse runs the source analysis headlessly, or prints the brief it would
// send. `prompt` exists so the instructions can be reviewed before any tokens
// are spent, and so a disagreement with the verdict can be traced to what the
// agent was actually asked.
func cmdAnalyse(name string, promptOnly bool) int {
	u, all, ok := find(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "patchlens: %s has no pending update\n", name)
		return 1
	}
	var n model.Notes
	if !agent.IsSystem(u) {
		n = adapters.For(u, false)
	}

	if promptOnly {
		fmt.Println(agent.Brief(u, n, all))
		return 0
	}

	// A stored analysis of these exact versions is shown rather than bought
	// again. PATCHLENS_FORCE re-runs when a second opinion is wanted.
	if os.Getenv("PATCHLENS_FORCE") == "" {
		if s, hit := agent.LoadStored(u); hit {
			emit(s.Text)
			fmt.Fprintln(os.Stderr,
				"  (stored analysis — PATCHLENS_FORCE=1 to re-run)")
			return 0
		}
	}

	if !agent.Available() {
		fmt.Fprintln(os.Stderr, "patchlens: claude CLI not found on PATH")
		return 1
	}

	// Ctrl-C cancels the child rather than orphaning it.
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Rendered Markdown for a human at a terminal; raw Markdown when the
	// output is going somewhere else. `patchlens analyse x > report.md` must
	// produce a Markdown file, not a file full of ANSI escapes.
	tty := isTerminal(os.Stdout)

	var md strings.Builder
	var trail []string
	for line := range agent.Run(ctx, u, n, all) {
		switch {
		case line.Kind == agent.Activity:
			// Tool calls go to stderr so redirecting stdout captures the
			// analysis alone while the progress trail still shows on screen.
			fmt.Fprintln(os.Stderr, "  \u2192", line.Text)
			trail = append(trail, line.Text)
		case line.Done:
		default:
			md.WriteString(line.Text + "\n")
			if !tty {
				fmt.Println(line.Text)
			}
		}
		if line.Done && line.Err != nil && !errors.Is(line.Err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "patchlens: agent failed:", line.Err)
			return 1
		}
	}

	if tty && md.Len() > 0 {
		emit(md.String())
	}
	agent.SaveStored(u, agent.Stored{Text: md.String(), Trail: trail})
	return 0
}

// emit writes the analysis: rendered for a reader at a terminal, raw Markdown
// when it is being redirected somewhere.
//
// No separate verdict banner here — the document already opens with the
// verdict as its first heading, and printing it twice in a row just looks like
// a bug. The interface does show a banner, because there it stays pinned above
// a pane the reader scrolls away from.
func emit(text string) {
	if !isTerminal(os.Stdout) {
		fmt.Println(text)
		return
	}
	fmt.Println(render.Markdown(render.Document(text), terminalWidth()))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// terminalWidth is the wrap width for rendered output, clamped so a very wide
// terminal does not produce lines too long to track across.
func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	if w > 100 {
		return 100
	}
	return w
}

// severityLine summarises a release's CVE severity distribution. Empty when
// the source publishes no severities, which is every source except Chrome.
func severityLine(r model.Release) string {
	if len(r.Severities) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, s := range r.Severities {
		counts[s]++
	}
	var parts []string
	for _, s := range []string{"Critical", "High", "Medium", "Low"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return fmt.Sprintf("%d CVEs: %s", len(r.CVEs), strings.Join(parts, ", "))
}

// capList keeps a long identifier list readable. A single Chrome release can
// name several hundred CVEs, and printing all of them buries every other line.
func capList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s … +%d more",
		strings.Join(items[:n], ", "), len(items)-n)
}

func cmdJSON() int {
	res := sources.Load(cacheTTL)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return 0
}

// cmdCount prints the number of updates carrying a CVE or a provenance change.
//
// Exits 1 when that count is non-zero, so a shell caller can branch on the
// exit status without parsing stdout.
func cmdCount() int {
	res := sources.Load(cacheTTL)
	n := 0
	for _, u := range res.Updates {
		if u.Flagged() {
			n++
		}
	}
	fmt.Println(n)
	if n > 0 {
		return 1
	}
	return 0
}

func cmdNotes(name string) int {
	res := sources.Load(cacheTTL)
	var found *model.Update
	for i := range res.Updates {
		if res.Updates[i].Name == name {
			found = &res.Updates[i]
			break
		}
	}
	if found == nil {
		fmt.Fprintf(os.Stderr, "patchlens: %s has no pending update\n", name)
		return 1
	}

	n := adapters.For(*found, false)
	fmt.Printf("%s  %s -> %s  (%s)\n", found.Name, found.Cur, found.New, found.Origin)
	fmt.Printf("source: %s  [%s]\n", n.Source, n.Kind)
	if len(found.CVEs) > 0 {
		fmt.Printf("tracker: %s — %s\n", found.Severity, capList(found.CVEs, 12))
	}
	if found.MaintainerWas != "" {
		fmt.Printf("maintainer changed: %s -> %s\n", found.MaintainerWas, found.Maintainer)
	}
	fmt.Println()

	if len(n.Releases) == 0 {
		msg := n.Err
		if msg == "" {
			msg = "upstream publishes no release notes"
		}
		fmt.Println(msg)
		return 0
	}
	for _, r := range n.Releases {
		fmt.Printf("── %s  %s\n", r.Version, r.Date)
		if len(r.CVEs) > 0 {
			// Severity counts first: with a few hundred identifiers, the
			// distribution is the actionable part and the list is reference.
			if s := severityLine(r); s != "" {
				fmt.Printf("   %s\n", s)
			}
			fmt.Printf("   %s\n", capList(r.CVEs, 12))
		}
		if b := strings.TrimSpace(r.Body); b != "" {
			for _, line := range strings.Split(b, "\n") {
				fmt.Println("   " + line)
			}
		}
		fmt.Println()
	}
	return 0
}
