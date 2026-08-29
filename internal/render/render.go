// Package render turns the agent's Markdown into something readable in a
// terminal, and pulls the verdict out of it.
//
// The analysis is written as Markdown because that is what the model is good
// at emitting and what stays readable when piped to a file. Showing the raw
// syntax to someone reading it on screen is the worst of both.
package render

import (
	"regexp"
	"strings"
	"sync"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	"github.com/charmbracelet/glamour/styles"
	"github.com/charmbracelet/lipgloss"
)

// Verdict is the recommendation the analysis leads with.
type Verdict string

const (
	InstallNow  Verdict = "INSTALL NOW"
	InstallSoon Verdict = "INSTALL SOON"
	Routine     Verdict = "ROUTINE"
	Wait        Verdict = "WAIT"
	Investigate Verdict = "INVESTIGATE"
)

// Ordered longest-first so "INSTALL NOW" is never matched as a bare "INSTALL"
// prefix of "INSTALL SOON".
var verdicts = []Verdict{InstallNow, InstallSoon, Investigate, Routine, Wait}

// Separators between the label and the answer are whatever the model reached
// for — a colon, an em dash, bold markers, or a mix ("**VERDICT — ROUTINE.**").
// The character class deliberately contains no letters, so prose such as
// "the verdict line means: INSTALL NOW" in the brief's own glossary cannot
// match and be mistaken for the answer.
var verdictRe = regexp.MustCompile(
	`(?i)VERDICT[\s:*.\x{2014}\x{2013}-]*(INSTALL NOW|INSTALL SOON|INVESTIGATE|ROUTINE|WAIT)`)

// FindVerdict returns the verdict stated in the text, if any.
//
// Scans for the labelled line rather than the first matching word anywhere:
// the body explains what each verdict means, so a naive word search finds
// "ROUTINE" in the glossary before the real answer.
func FindVerdict(md string) (Verdict, bool) {
	m := verdictRe.FindStringSubmatch(md)
	if m == nil {
		return "", false
	}
	want := strings.ToUpper(m[1])
	for _, v := range verdicts {
		if string(v) == want {
			return v, true
		}
	}
	return "", false
}

var headingRe = regexp.MustCompile(`(?m)^#{1,6}\s`)

// Document trims the agent's running commentary off the front of its answer.
//
// The stream carries every word the agent says, including the asides it makes
// between tool calls — "Got the real diff, let me filter out the CI noise".
// That is useful to watch live and useless above a finished report. The answer
// itself begins at its first Markdown heading, so everything before that is
// narration and is dropped.
//
// Falls back to the whole text when there is no heading at all, since some
// answer is always better than none.
func Document(md string) string {
	if loc := headingRe.FindStringIndex(md); loc != nil {
		return strings.TrimLeft(md[loc[0]:], "\n")
	}
	return md
}

// Urgency grades a verdict for display: 2 act now, 1 worth attention, 0 fine.
func Urgency(v Verdict) int {
	switch v {
	case InstallNow, Investigate:
		return 2
	case InstallSoon, Wait:
		return 1
	}
	return 0
}

var (
	mu       sync.Mutex
	renderer *glamour.TermRenderer
	width    int
	// Rendering is pure for a given (text, width), and the pane re-renders on
	// every streamed line. Memoising the last result keeps that at one render
	// per change instead of one per event.
	lastIn, lastOut string
	lastWidth       int
)

// headings replaces the built-in heading prefixes.
//
// Both stock styles render a level-two heading as a coloured "## VERDICT",
// keeping the hashes and merely tinting them. That is still Markdown syntax on
// screen, which is the thing this package exists to get rid of. A vertical bar
// reads as a heading without spelling out how the heading was written, and
// matches the release-note headers in the other pane.
func headings(cfg *ansi.StyleConfig) {
	for i, h := range []*ansi.StyleBlock{
		&cfg.H1, &cfg.H2, &cfg.H3, &cfg.H4, &cfg.H5, &cfg.H6,
	} {
		prefix := "▌ "
		if i > 1 {
			prefix = "  "
		}
		h.Prefix = prefix
		h.Suffix = ""
		h.Bold = boolPtr(true)
	}
}

func boolPtr(b bool) *bool { return &b }

// Markdown renders md for a terminal of the given width.
//
// Falls back to the raw text if glamour cannot be constructed — unreadable
// styling is a far better failure than an empty analysis pane.
func Markdown(md string, w int) string {
	if strings.TrimSpace(md) == "" {
		return ""
	}
	if w < 20 {
		w = 20
	}

	mu.Lock()
	defer mu.Unlock()

	if md == lastIn && w == lastWidth && lastOut != "" {
		return lastOut
	}
	if renderer == nil || width != w {
		// The style is chosen explicitly rather than with WithAutoStyle.
		// Auto-detection inspects stdout, and when it decides there is no
		// terminal it selects a plain style that emits the Markdown source
		// almost verbatim — headings still spelled "##", emphasis still
		// spelled "**". That is precisely the output this package exists to
		// avoid, and it fails in exactly the environments hardest to notice it
		// in. lipgloss has already resolved light-versus-dark for the rest of
		// the interface, so reuse its answer and always render.
		cfg := styles.LightStyleConfig
		if lipgloss.HasDarkBackground() {
			cfg = styles.DarkStyleConfig
		}
		headings(&cfg)
		r, err := glamour.NewTermRenderer(
			glamour.WithStyles(cfg),
			glamour.WithWordWrap(w),
		)
		if err != nil {
			return md
		}
		renderer, width = r, w
	}

	out, err := renderer.Render(md)
	if err != nil {
		return md
	}
	// glamour pads every document with a leading blank line and trailing
	// newlines; in a scrolling pane that reads as the output having stopped.
	out = strings.Trim(out, "\n")
	lastIn, lastOut, lastWidth = md, out, w
	return out
}
