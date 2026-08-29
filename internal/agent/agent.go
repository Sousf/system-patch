// Package agent dispatches a Claude Code agent to analyse an update at source.
//
// This is the step no feed can do for you. The adapters report what upstream
// *says* changed; the agent goes and reads what actually changed — the diff
// between the installed tag and the candidate tag — and judges whether the
// update is worth taking. That distinction matters most in exactly the case
// this tool was built for: a compromised package ships with entirely normal
// release notes, because upstream was never touched.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sousf/patchlens/internal/adapters"
	"github.com/Sousf/patchlens/internal/cache"
	"github.com/Sousf/patchlens/internal/model"
	"github.com/Sousf/patchlens/internal/sources"
)

// Available reports whether the claude CLI is on PATH.
func Available() bool {
	_, err := exec.LookPath("claude")
	return err == nil
}

// defaultModel is pinned rather than inherited from the user's Claude Code
// settings.
//
// Inheriting meant the analysis silently ran on whatever the machine happened
// to be configured for, so verdicts were not comparable between runs or
// between machines.
//
// Sonnet rather than Opus, measured rather than assumed. Both were run on the
// same libheif security release: Opus took 65 turns and about $5.19, Sonnet 32
// turns and $1.14, and both reached INSTALL NOW having noticed that the CVE the
// Arch tracker attaches to the package is a stale 2020 entry irrelevant to this
// update — the one finding that justifies reading source over reading feeds.
// The saving is 4.5x, not the 1.7x the per-token rates alone suggest, because
// the cheaper model also did less work to get there.
//
// Override with PATCHLENS_MODEL for a package that deserves a second opinion.
const defaultModel = "claude-sonnet-5"

// Effort is the real cost dial, not the model tier.
//
// A measured run cost about $5.19 on Opus and would have been $3.11 on Sonnet
// — only 40% less, because the bill is dominated by how much the agent reads
// and writes (4M cached input tokens, 50K output), not by the per-token rate.
// Effort moves that volume directly, so lowering it saves more than
// downgrading while keeping the model that can actually reach the answer.
//
// Flagged updates carry CVEs or a maintainer change and get the full pass.
// Routine version bumps get a cheaper one.
const (
	effortFlagged = "high"
	effortRoutine = "medium"
)

// settings resolves model and effort, letting the environment override both so
// the choice is the user's without a rebuild.
func settings(u model.Update) (modelID, effort string) {
	modelID = os.Getenv("PATCHLENS_MODEL")
	if modelID == "" {
		modelID = defaultModel
	}
	effort = os.Getenv("PATCHLENS_EFFORT")
	if effort == "" {
		effort = effortRoutine
		// The whole-transaction assessment always gets the full pass: it is
		// the highest-stakes question the tool answers, and the one whose
		// mistakes are hardest to undo.
		if u.Flagged() || IsSystem(u) {
			effort = effortFlagged
		}
	}
	return modelID, effort
}

// workRoot is the parent for per-run scratch directories. Under the cache, so
// anything a killed run leaves behind is swept up with the rest of the cache
// rather than accumulating in the user's home.
func workRoot() string {
	p := filepath.Join(cache.Dir(), "work")
	if os.MkdirAll(p, 0o700) != nil {
		return "" // MkdirTemp falls back to the system temp dir
	}
	return p
}

// Tools pre-approved for the analysis, so it runs without prompting.
//
// This list grants; it does not confine. Observed runs also reach for awk,
// python3 and mkdir through Bash, which is reasonable for unpacking a diff —
// so treat Bash here as general shell access, not as a whitelist of two
// commands.
var allowedTools = []string{
	"WebFetch", "WebSearch", "Read", "Grep", "Glob",
	"Bash(git:*)", "Bash(curl:*)",
	// Checksum and archive tools. Without these a run reports "I could not
	// verify the tarball checksum, the sandbox denied it" — observed on
	// libaio, where confirming the PKGBUILD's sums after an upstream host
	// change was the whole supply-chain question.
	"Bash(sha256sum:*)", "Bash(sha512sum:*)", "Bash(b2sum:*)",
	"Bash(md5sum:*)", "Bash(tar:*)", "Bash(file:*)", "Bash(diff:*)",
}

// Tools denied outright. This is the half that actually constrains.
//
// The analysis reads and reports; it has no business writing files or driving
// the package manager, and the whole point of the tool is undermined if
// "should I install this?" can install it. Editing tools are denied by name,
// which is exact. The Bash patterns are defence in depth rather than a
// guarantee — a determined shell can spell a command more than one way — so
// the real containment is the scratch working directory the run is confined
// to, not this list.
// Both spellings of each Bash pattern are listed. `--disallowed-tools`
// documents its examples as `Bash(git *)` while settings files use
// `Bash(git:*)`, and a run was observed executing rm despite the colon form
// being denied — so which one the CLI honours is not something to assume.
// Listing both costs nothing; relying on either alone evidently does.
var disallowedTools = []string{
	"Edit", "Write", "NotebookEdit",
	"Bash(sudo:*)", "Bash(sudo *)",
	"Bash(pacman:*)", "Bash(pacman *)",
	"Bash(paru:*)", "Bash(paru *)",
	"Bash(makepkg:*)", "Bash(makepkg *)",
}

// Prompt builds the analysis brief.
//
// Everything the agent would otherwise have to rediscover is handed to it
// up front — versions, forge URL, diff URL, tracker CVEs, provenance — so its
// budget goes on reading code rather than on working out what to read.
func Prompt(u model.Update, n model.Notes) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Assess whether this Arch Linux package update is worth installing.\n\n")
	fmt.Fprintf(&b, "PACKAGE\n")
	fmt.Fprintf(&b, "  name:      %s\n", u.Name)
	fmt.Fprintf(&b, "  origin:    %s\n", u.Origin)
	fmt.Fprintf(&b, "  installed: %s\n", u.Cur)
	fmt.Fprintf(&b, "  candidate: %s\n", u.New)
	if u.URL != "" {
		fmt.Fprintf(&b, "  upstream:  %s\n", u.URL)
	}
	if cu := adapters.CompareURL(u, n); cu != "" {
		fmt.Fprintf(&b, "  diff:      %s\n", cu)
		fmt.Fprintf(&b, "  raw diff:  %s.diff\n", cu)
	}

	if len(u.CVEs) > 0 {
		fmt.Fprintf(&b, "\nARCH SECURITY TRACKER (severity %s)\n  %s\n",
			u.Severity, strings.Join(u.CVEs, ", "))
	}

	if u.MaintainerWas != "" {
		fmt.Fprintf(&b, "\nPROVENANCE ALERT\n")
		fmt.Fprintf(&b, "  The AUR maintainer changed since the last check: %q -> %q.\n",
			u.MaintainerWas, u.Maintainer)
		fmt.Fprintf(&b, "  Treat the PKGBUILD as untrusted until you have read it. "+
			"Adopting orphaned packages was the vector of the July 2026 AUR malware wave.\n")
	}
	if u.OutOfDate {
		fmt.Fprintf(&b, "\n  The AUR package is community-flagged out-of-date.\n")
	}

	// Everything below is computed locally, so the agent spends its budget
	// judging consequences rather than rediscovering the dependency graph.
	br := sources.Assess(u)
	fmt.Fprintf(&b, "\nWHAT DEPENDS ON THIS (from the local database)\n")
	if len(br.Deps.RequiredBy) == 0 && len(br.Deps.OptionalFor) == 0 {
		fmt.Fprintf(&b, "  nothing installed depends on it\n")
	}
	if len(br.Deps.RequiredBy) > 0 {
		fmt.Fprintf(&b, "  required by:  %s\n", strings.Join(br.Deps.RequiredBy, " "))
	}
	if len(br.Deps.OptionalFor) > 0 {
		fmt.Fprintf(&b, "  optional for: %s\n", strings.Join(br.Deps.OptionalFor, " "))
	}
	if len(br.AtRiskBy) > 0 {
		fmt.Fprintf(&b, "  OF THOSE, FROM THE AUR: %s\n", strings.Join(br.AtRiskBy, " "))
		fmt.Fprintf(&b, "  (a system upgrade rebuilds repo packages together; these are "+
			"not rebuilt for you and are where breakage actually lands)\n")
	}
	if len(br.Sonames) > 0 {
		fmt.Fprintf(&b, "\n  SONAME CHANGES IN THIS UPDATE:\n")
		for _, s := range br.Sonames {
			fmt.Fprintf(&b, "    %s\n", s)
		}
		fmt.Fprintf(&b, "  Anything linked against the old soname stops loading "+
			"until it is rebuilt.\n")
	} else if u.Origin == model.Repo && len(br.Deps.Provides) > 0 {
		fmt.Fprintf(&b, "  no soname changes: %s\n", strings.Join(br.Deps.Provides, " "))
	}

	if len(n.Releases) > 0 {
		fmt.Fprintf(&b, "\nUPSTREAM RELEASES IN RANGE (%s, %s)\n", n.Source, n.Kind)
		for i, r := range n.Releases {
			if i >= 8 {
				fmt.Fprintf(&b, "  ... and %d more\n", len(n.Releases)-i)
				break
			}
			fmt.Fprintf(&b, "  %s (%s)", r.Version, r.Date)
			if len(r.CVEs) > 0 {
				fmt.Fprintf(&b, " — %d CVEs", len(r.CVEs))
			}
			fmt.Fprintln(&b)
		}
	} else if n.Err != "" {
		fmt.Fprintf(&b, "\nNo upstream release notes: %s (%s)\n", n.Err, n.Source)
	}

	b.WriteString(`
TASK
Read the actual source diff, not just the release notes.

Finish investigating before you write anything. Then lead the response with
the conclusion — the reader wants the answer first and the evidence after.

Reply in GitHub-flavoured Markdown, opening with exactly this shape:

## <package name> — <what it is, in half a line>
Two or three sentences of plain English: what this software actually does, and
what it is doing on a desktop Arch machine. Assume the reader has never heard
of it and does not know the jargon of its field. No version numbers here, no
CVEs, no opinion — just what the thing is for.

## VERDICT: <INSTALL NOW|INSTALL SOON|ROUTINE|WAIT|INVESTIGATE>
One sentence saying why.

**Breaks:** either the single word NOTHING, or a plain-English list of what
stops working and what to do about it. Base this on the dependency and soname
data above, not on guesswork. A soname change with AUR packages linked against
it is the case that actually bites; repository packages are rebuilt together
and normally are not.

Then, under their own headings:

1. WHAT CHANGED — the substantive changes, grouped. Ignore version bumps,
   formatting and CI churn.
2. WHY IT WAS PUSHED — the real reason for the release. If CVEs are listed,
   find what each one actually fixes in the code.
3. SECURITY IMPACT — does this fix a vulnerability reachable in normal desktop
   use, and is there evidence of active exploitation? Say plainly when a CVE is
   not reachable in this configuration.
4. SUPPLY-CHAIN CHECK — anything in the diff or PKGBUILD that does not belong:
   new network calls, new install-time scripts, obfuscated blobs, changed source
   URLs, new maintainers, added binary artifacts. State explicitly if you find
   nothing.
5. REGRESSION RISK — breaking changes, config migrations, known post-release
   bug reports or reverts.
6. WILL ANYTHING ELSE BREAK — work through the dependency data above. For each
   reverse dependency that is genuinely at risk, say what the user will observe
   (a program failing to start, a missing feature, a rebuild needed) and the
   command that fixes it. If the answer is that nothing breaks, say so and say
   why — "no soname change, and the only consumers are repository packages
   upgraded in the same transaction" is a real answer.

The verdict line means: INSTALL NOW, a vulnerability reachable in normal use;
INSTALL SOON, a real fix with no urgent exposure; ROUTINE, no security content;
WAIT, a known regression makes it worth delaying; INVESTIGATE, something in the
diff or its provenance does not add up.

You are running in an empty scratch directory that is deleted afterwards.
Download and unpack whatever you need into it. Do not write anywhere else.

Rules: base every claim on something you actually read, and cite the file or
commit. If you could not fetch the diff, say so rather than reasoning from the
version numbers alone. An honest "no signal available" is worth more here than
a confident guess, because the answer decides whether real code gets installed.
Be concise; no preamble.`)

	return b.String()
}

// Stored is a finished analysis, kept on disk.
//
// Cached at all because a run costs real money and takes minutes: asking for
// an analysis of a package already analysed at these exact versions should
// return what it said, not silently spend it again. Keyed on the version pair,
// so it expires the moment either side moves.
type Stored struct {
	Text  string   `json:"text"`
	Trail []string `json:"trail,omitempty"`
}

func storeKey(u model.Update) string {
	return "analysis-" + u.Name + "@" + u.Cur + ".." + u.New
}

// LoadStored returns a previous analysis of this exact update, if there is one.
func LoadStored(u model.Update) (Stored, bool) {
	var s Stored
	if cache.Get(storeKey(u), 90*24*time.Hour, &s) && strings.TrimSpace(s.Text) != "" {
		return s, true
	}
	return Stored{}, false
}

// SaveStored records a finished analysis.
func SaveStored(u model.Update, s Stored) {
	if strings.TrimSpace(s.Text) == "" {
		return
	}
	cache.Put(storeKey(u), s)
}

// SystemUpdate is the synthetic entry standing for "upgrade everything".
//
// Not a package. It occupies the first row of the list because "is it safe to
// run a full upgrade right now" is the question a per-package view never
// answers: the risks that matter at that level — an announcement demanding
// manual intervention, a library soname moving under the AUR packages nobody
// rebuilds, a kernel replacing modules the running system still needs — are
// properties of the transaction, not of any package in it.
var SystemUpdate = model.Update{
	Name:   "full system upgrade",
	Origin: "system",
}

// IsSystem reports whether an update is the synthetic whole-system entry.
func IsSystem(u model.Update) bool { return u.Origin == SystemUpdate.Origin }

// SystemEntry builds the synthetic row for a given pending set.
//
// The version fields carry a count and a digest of the transaction's contents
// rather than being left blank. Analyses are cached by name@cur..new, and a
// blank pair would make every future transaction look like the same one — so a
// verdict about yesterday's forty packages would be served for today's fifty.
// Digesting the set makes the cache invalidate exactly when the answer could
// have changed.
func SystemEntry(ups []model.Update) model.Update {
	h := fnv.New64a()
	n := 0
	for _, u := range ups {
		if IsSystem(u) {
			continue
		}
		n++
		fmt.Fprintf(h, "%s@%s;", u.Name, u.New)
	}
	u := SystemUpdate
	u.Cur = fmt.Sprintf("%d packages", n)
	u.New = fmt.Sprintf("%x", h.Sum64())
	return u
}

// SystemPrompt briefs the agent on the entire pending transaction.
func SystemPrompt(ups []model.Update) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Assess what happens if this Arch Linux system is fully "+
		"upgraded right now.\n\n")
	fmt.Fprintf(&b, "The command would be `paru -Syu`: every repository package "+
		"and every AUR package, in one transaction.\n")

	var repo, aur []model.Update
	for _, u := range ups {
		if IsSystem(u) {
			continue
		}
		if u.Origin == model.AUR {
			aur = append(aur, u)
		} else {
			repo = append(repo, u)
		}
	}
	fmt.Fprintf(&b, "\nSCALE\n  %d repository packages, %s\n",
		len(repo), plural(len(aur), "AUR package"))

	// The AUR half is listed in full however long it gets. These are the
	// packages nothing rebuilds automatically, so they are the ones the answer
	// turns on.
	if len(aur) > 0 {
		fmt.Fprintf(&b, "\nAUR PACKAGES BEING REBUILT\n")
		for _, u := range aur {
			fmt.Fprintf(&b, "  %s  %s -> %s\n", u.Name, u.Cur, u.New)
		}
	}

	fmt.Fprintf(&b, "\nSECURITY-FLAGGED IN THIS SET\n")
	flagged := 0
	for _, u := range ups {
		if IsSystem(u) || !u.Flagged() {
			continue
		}
		flagged++
		switch {
		case len(u.CVEs) > 0:
			fmt.Fprintf(&b, "  %s — %s, %d CVEs (Arch tracker)\n",
				u.Name, u.Severity, len(u.CVEs))
		case u.UpstreamCVEs > 0:
			fmt.Fprintf(&b, "  %s — %d CVEs (vendor release notes)\n",
				u.Name, u.UpstreamCVEs)
		case u.MaintainerWas != "":
			fmt.Fprintf(&b, "  %s — AUR maintainer changed: %s -> %s\n",
				u.Name, u.MaintainerWas, u.Maintainer)
		}
	}
	if flagged == 0 {
		fmt.Fprintf(&b, "  none\n")
	}

	// Kernel updates are called out because their failure mode is delayed and
	// confusing: modules for the running kernel are replaced on disk, so
	// hotplugging hardware or loading a module fails until reboot.
	for _, u := range repo {
		if u.Name == "linux" || u.Name == "linux-lts" || strings.HasPrefix(u.Name, "linux-") {
			fmt.Fprintf(&b, "\nKERNEL\n  %s %s -> %s (running kernel's modules are "+
				"replaced on disk; reboot required)\n", u.Name, u.Cur, u.New)
			break
		}
	}

	if news := sources.News(8); len(news) > 0 {
		fmt.Fprintf(&b, "\nARCH NEWS, MOST RECENT FIRST\n")
		for _, it := range news {
			mark := " "
			if it.RequiresIntervention() {
				mark = "!"
			}
			fmt.Fprintf(&b, " %s %s (%s)\n    %s\n    %s\n",
				mark, it.Title, it.Date, it.Link, truncate(it.Summary, 400))
		}
		fmt.Fprintf(&b, "  Items marked ! announce a manual step. Check whether each "+
			"one applies to THIS machine — most do not.\n")
	}

	fmt.Fprintf(&b, "\nFULL REPOSITORY LIST\n")
	for i, u := range repo {
		if i >= 60 {
			fmt.Fprintf(&b, "  ... and %d more\n", len(repo)-i)
			break
		}
		fmt.Fprintf(&b, "  %s %s -> %s\n", u.Name, u.Cur, u.New)
	}

	b.WriteString(`
TASK
Work out what actually happens if this upgrade runs now. Investigate before
writing: check the news items against the installed packages, and check whether
any library in this set is moving its soname under an AUR package. You can read
the local database with pacman -Qi / -Si / -Qmq and pactree.

Reply in GitHub-flavoured Markdown, opening with exactly this shape:

## Full system upgrade — <n> packages
Two or three sentences of plain English on what this transaction is and the
shape of it: mostly routine, or carrying something that needs care.

## VERDICT: <INSTALL NOW|INSTALL SOON|ROUTINE|WAIT|INVESTIGATE>
One sentence saying why.

**Breaks:** the single word NOTHING, or a plain list of what will stop working
and what to do about it.

**Do first:** any step that must happen before upgrading, or NOTHING.

Then, under their own headings:

1. WHAT YOU ARE GETTING — the security content worth having, briefly. Lead with
   anything reachable in normal desktop use.
2. MANUAL INTERVENTION — for each news item, whether it applies to this machine
   and what to do. Say plainly when one does not apply.
3. AUR FALLOUT — which AUR packages are at risk from a repository library
   moving, and which will simply rebuild. These are the ones no upgrade fixes
   for you.
4. AFTERWARDS — reboots, service restarts, .pacnew configuration files, and
   anything that will look broken until a step is taken.
5. IF IT GOES WRONG — the specific recovery path for this transaction. Note
   that this machine has snapper with snap-pac, so pacman takes a pre-upgrade
   snapshot automatically.

Rules: base every claim on something you actually checked, and say which. Do
not warn about risks you have not verified apply here — a list of things that
could theoretically go wrong is noise, and it trains the reader to skip the one
warning that matters. Be concise.`)

	return b.String()
}

// plural renders a count with its noun, since "1 AUR packages" in a brief
// reads as carelessness and invites the reader to discount the rest.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "\u2026"
}

// Brief picks the right prompt for an update.
//
// One place decides, so the preview (`patchlens prompt`) and the run can never
// disagree about what was asked — the preview exists precisely so a verdict can
// be traced back to its instructions.
func Brief(u model.Update, n model.Notes, all []model.Update) string {
	if IsSystem(u) {
		return SystemPrompt(all)
	}
	return Prompt(u, n)
}

// Kind separates the agent's findings from the noise of it working.
type Kind int

const (
	// Text is the agent's own prose — the answer.
	Text Kind = iota
	// Activity is a tool call it made along the way. Shown dimmed, because on
	// a pass that runs for minutes the difference between "working" and "hung"
	// is the only thing the reader wants to know.
	Activity
)

// Line is one chunk of agent output.
type Line struct {
	Kind Kind
	Text string
	Err  error
	Done bool
}

// The stream-json envelope, decoded loosely: only the fields that drive the
// display are named, so an added event type or field cannot break parsing.
type event struct {
	Type    string `json:"type"`
	Message struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	} `json:"message"`
	Subtype  string  `json:"subtype"`
	IsError  bool    `json:"is_error"`
	Result   string  `json:"result"`
	CostUSD  float64 `json:"total_cost_usd"`
	Duration int64   `json:"duration_api_ms"`
	NumTurns int     `json:"num_turns"`
}

// summarise renders a tool call as one short line.
//
// The first field that identifies the target is used, so a WebFetch reads as
// its URL and a Bash call as its command, rather than as a wall of JSON.
func summarise(name string, input json.RawMessage) string {
	var m map[string]any
	_ = json.Unmarshal(input, &m)
	for _, k := range []string{"url", "command", "pattern", "file_path", "query", "path"} {
		if v, ok := m[k].(string); ok && v != "" {
			v = strings.ReplaceAll(v, "\n", " ")
			if len(v) > 110 {
				v = v[:109] + "…"
			}
			return name + "  " + v
		}
	}
	return name
}

// Run streams the agent's analysis.
//
// Uses stream-json rather than the default text output: in text mode the CLI
// prints nothing at all until the whole run finishes, which for a job that
// legitimately takes minutes is indistinguishable from a hang. Cancelling ctx
// kills the child process.
func Run(ctx context.Context, u model.Update, n model.Notes, allUpdates []model.Update) <-chan Line {
	ch := make(chan Line, 64)

	go func() {
		defer close(ch)

		modelID, effort := settings(u)
		brief := Brief(u, n, allUpdates)
		args := []string{
			"-p", brief,
			"--output-format", "stream-json",
			// stream-json in print mode requires --verbose; without it the CLI
			// refuses to start rather than falling back.
			"--verbose",
			"--model", modelID,
			"--effort", effort,
		}
		args = append(args, "--allowed-tools")
		args = append(args, allowedTools...)
		args = append(args, "--disallowed-tools")
		args = append(args, disallowedTools...)
		cmd := exec.CommandContext(ctx, "claude", args...)

		// Run in a scratch directory rather than wherever patchlens happens to
		// have been launched from. The agent downloads diffs and unpacks
		// sources as it works, and without this it does that in the user's
		// current project — observed creating .patchlens-tmp/ and tmp_libheif/
		// inside this very repository. Removed when the run ends.
		if dir, err := os.MkdirTemp(workRoot(), "run-"); err == nil {
			cmd.Dir = dir
			defer os.RemoveAll(dir)
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			ch <- Line{Err: err, Done: true}
			return
		}
		// Discarded deliberately: the CLI writes MCP connection chatter here
		// that would otherwise be interleaved with the analysis.
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			ch <- Line{Err: err, Done: true}
			return
		}

		send := func(l Line) bool {
			select {
			case ch <- l:
				return true
			case <-ctx.Done():
				return false
			}
		}

		sc := bufio.NewScanner(stdout)
		// One event per line, and a single assistant turn carrying the whole
		// verdict comfortably exceeds bufio's 64 KB default. A truncated
		// verdict would be worse than a slow one.
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			var e event
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			switch e.Type {
			case "assistant":
				for _, c := range e.Message.Content {
					switch c.Type {
					case "text":
						for _, line := range strings.Split(c.Text, "\n") {
							if !send(Line{Kind: Text, Text: line}) {
								return
							}
						}
					case "tool_use":
						if !send(Line{Kind: Activity,
							Text: summarise(c.Name, c.Input)}) {
							return
						}
					}
				}
			case "result":
				if e.IsError && e.Result != "" {
					if !send(Line{Kind: Text, Text: e.Result}) {
						return
					}
				}
				// Report the spend. A tool that asks you to press a key
				// costing real money should say what the last press cost
				// rather than leave you to find out on a bill.
				if e.CostUSD > 0 {
					if !send(Line{Kind: Activity, Text: fmt.Sprintf(
						"%s · effort %s · %d turns · %.0fs · $%.2f",
						modelID, effort, e.NumTurns,
						float64(e.Duration)/1000, e.CostUSD)}) {
						return
					}
				}
			}
		}

		err = cmd.Wait()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		ch <- Line{Err: err, Done: true}
	}()

	return ch
}
