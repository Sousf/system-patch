// Package model holds the records every other package exchanges.
//
// Kept dependency-free so the cache can serialise these directly and the UI
// can render them without importing the network layer.
package model

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Origin distinguishes where an update came from, which decides both how its
// metadata is enriched and which upgrade command is safe for it.
type Origin string

const (
	Repo Origin = "repo"
	AUR  Origin = "aur"
	// Flatpak apps and runtimes. A separate manager with its own remotes, so
	// `pacman -Syu` and `paru -Syu` never touch them however complete they
	// look — which is exactly why they go stale unnoticed.
	Flatpak Origin = "flatpak"
	// Snap packages, likewise their own manager and their own store.
	//
	// Declared rather than spelled Origin("snap") at each use, as it was: the
	// partitions that classify updates all ended in `default: repo`, so snaps
	// were counted as repository packages in the interface and briefed to the
	// agent under FULL REPOSITORY LIST.
	Snap Origin = "snap"
)

// SystemOrigins are the origins a distribution's own package manager owns, and
// therefore the only ones its local database can answer questions about.
func (o Origin) System() bool { return o == Repo || o == AUR }

// Update is one pending package update.
type Update struct {
	Name   string `json:"name"`
	Cur    string `json:"cur"`
	New    string `json:"new"`
	Origin Origin `json:"origin"`
	URL    string `json:"url"`

	// Manager names the tool that reported this update, e.g. "apt" or
	// "pacman + AUR". Display only.
	//
	// Kept separate from Origin, which is semantic and drives behaviour: which
	// upgrade command is safe for one package, whether a system upgrade
	// rebuilds it, whether the Security Tracker covers it. Several managers
	// share one origin, so labelling the interface with Origin filed every apt
	// package on Ubuntu under a tab called "repo", which is an Arch
	// distinction that has no meaning there.
	Manager string `json:"manager,omitempty"`

	// From arch-audit. Repo packages only: the Arch Security Tracker has no
	// notion of an AUR package, which is the blind spot this tool exists to
	// cover.
	CVEs     []string `json:"cves,omitempty"`
	Severity string   `json:"severity,omitempty"`

	// AUR provenance. MaintainerWas is non-empty only when the package changed
	// hands since the last run — a supply-chain signal independent of anything
	// the version delta says.
	Maintainer    string `json:"maintainer,omitempty"`
	MaintainerWas string `json:"maintainerWas,omitempty"`
	OutOfDate     bool   `json:"outOfDate,omitempty"`

	// Filled by the upstream enrichment pass, and kept separate from CVEs
	// because the two have different provenance: CVEs came from the Arch
	// Security Tracker, these came from the vendor's own release notes. An AUR
	// package can only ever have these, since the Tracker does not cover the
	// AUR at all — which is exactly why a package like google-chrome would
	// otherwise sit in the list looking unremarkable.
	UpstreamCVEs int  `json:"upstreamCves,omitempty"`
	UpstreamKind Kind `json:"upstreamKind,omitempty"`
}

// Flagged reports whether anything about this update warrants attention beyond
// "a newer version exists".
func (u Update) Flagged() bool { return u.Reason() != ReasonNone }

// Why an update is flagged, in the order the reasons take precedence.
type ReasonKind int

const (
	ReasonNone ReasonKind = iota
	ReasonTrackerCVE
	ReasonUpstreamCVE
	ReasonMaintainer
	ReasonSuspected
	ReasonOutOfDate
)

// Reason names why this update is flagged, or ReasonNone.
//
// One source for a set that four places used to re-enumerate by hand, and two
// had drifted: `list` printed a blank mark for a suspected-only package that
// `count` counted, and the brief's flagged counter fired for five reasons
// while its printer covered three, so a transaction flagged only by an
// out-of-date package emitted a bare header with no rows under it.
func (u Update) Reason() ReasonKind {
	switch {
	case len(u.CVEs) > 0:
		return ReasonTrackerCVE
	case u.UpstreamCVEs > 0:
		return ReasonUpstreamCVE
	case u.MaintainerWas != "":
		return ReasonMaintainer
	case u.UpstreamKind == KindSuspected:
		return ReasonSuspected
	case u.OutOfDate:
		return ReasonOutOfDate
	}
	return ReasonNone
}

// Explain renders the reason as one plain-text line, empty when unflagged.
func (u Update) Explain() string {
	switch u.Reason() {
	case ReasonTrackerCVE:
		sev := u.Severity
		if sev == "" {
			sev = "unrated"
		}
		return fmt.Sprintf("%s, %d CVEs (tracker)", sev, len(u.CVEs))
	case ReasonUpstreamCVE:
		return fmt.Sprintf("%d CVEs (upstream)", u.UpstreamCVEs)
	case ReasonMaintainer:
		return "maintainer " + u.MaintainerWas + " -> " + u.Maintainer
	case ReasonSuspected:
		return "release notes read security-relevant, no CVE named"
	case ReasonOutOfDate:
		return "flagged out-of-date"
	}
	return ""
}

// Severities are the advisory ratings, most severe first. One list, because
// two display loops and a rank map had drifted: both loops stopped at "Low",
// so an unrated advisory was counted into a CVE total it could never appear
// as a segment of.
var Severities = []string{"Critical", "High", "Medium", "Low", "Unknown"}

// Kind describes how much confidence the caller may place in a Notes value.
type Kind string

const (
	// KindSecurity means an adapter returned explicit CVE identifiers.
	KindSecurity Kind = "security"
	// KindSuspected means the prose reads security-relevant but names no
	// identifier. The distinction matters to someone deciding between patching
	// now and patching on Sunday, so it is never collapsed into KindSecurity.
	KindSuspected Kind = "suspected"
	// KindChangelog means real release notes with no security signal.
	KindChangelog Kind = "changelog"
	// KindNone means no adapter matched, or upstream publishes nothing. A
	// first-class outcome, not an error: reporting "no security signal exists"
	// is honest, whereas synthesising an all-clear from an absent feed is the
	// failure this constant exists to prevent.
	KindNone Kind = "none"
)

// Release is a single upstream release sitting between installed and available.
type Release struct {
	Version string   `json:"version"`
	Date    string   `json:"date"`
	Body    string   `json:"body"`
	CVEs    []string `json:"cves,omitempty"`
	// Chrome states a severity per CVE; GitHub and GitLab do not, so this stays
	// empty for them rather than being guessed.
	Severities map[string]string `json:"severities,omitempty"`
}

// Notes is everything the changelog adapters found for one update.
type Notes struct {
	Source   string    `json:"source"`
	Kind     Kind      `json:"kind"`
	Releases []Release `json:"releases,omitempty"`
	// Err explains an empty Releases slice. "Unreachable" and "nothing found"
	// mean very different things to someone deciding whether to patch, so the
	// two are never rendered identically.
	Err string `json:"err,omitempty"`
}

// Reason explains an empty Releases slice in one line.
//
// The distinction it encodes is load-bearing: a non-empty Err means the source
// was unreachable, an empty one means upstream publishes nothing. Both files
// that rendered it carried the same four lines and the same string literal.
func (n Notes) Reason() string {
	if n.Err != "" {
		return n.Err
	}
	return "upstream publishes no release notes"
}

var tagRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)
var pkgrelRe = regexp.MustCompile(`-\d+$`)

// UpstreamVersion strips the distribution's packaging from a version: a pacman
// epoch ("1:"), a pkgrel ("-2") and a tag's leading "v".
//
// Exported because adapters needs the same transformation to build a forge tag,
// and had its own copy of the regexp and the epoch cut. The copy dropped the
// guard below, which keeps a hyphen before the colon from being read as an
// epoch marker.
func UpstreamVersion(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ":"); i >= 0 && !strings.Contains(s[:i], "-") {
		s = s[i+1:]
	}
	s = pkgrelRe.ReplaceAllString(s, "")
	return strings.TrimLeft(s, "vV")
}

// VParts reduces a version string to a comparable sequence of integers.
//
// Strips a pacman epoch ("1:"), a pkgrel ("-2") and a tag's leading "v", then
// takes the leading dotted-numeric run. Deliberately tolerant: this decides
// which releases fall between installed and available, and an unparseable tag
// scheme should drop that one entry rather than abort the whole lookup.
func VParts(s string) []int {
	m := tagRe.FindStringSubmatch(UpstreamVersion(s))
	if m == nil {
		return nil
	}
	var out []int
	for _, p := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// VCmp compares two parsed versions. Shorter prefixes sort lower, so 1.2 < 1.2.1.
func VCmp(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// InRange reports whether v is newer than installed and no newer than available.
func InRange(v, cur, next string) bool {
	pv, pc := VParts(v), VParts(cur)
	if len(pv) == 0 || len(pc) == 0 {
		return false
	}
	if VCmp(pv, pc) <= 0 {
		return false
	}
	if pn := VParts(next); len(pn) > 0 && VCmp(pv, pn) > 0 {
		return false
	}
	return true
}
