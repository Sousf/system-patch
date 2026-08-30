// Package model holds the records every other package exchanges.
//
// Kept dependency-free so the cache can serialise these directly and the UI
// can render them without importing the network layer.
package model

import (
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
)

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
func (u Update) Flagged() bool {
	return len(u.CVEs) > 0 || u.UpstreamCVEs > 0 ||
		u.UpstreamKind == KindSuspected ||
		u.MaintainerWas != "" || u.OutOfDate
}

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

var tagRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)
var pkgrelRe = regexp.MustCompile(`-\d+$`)

// VParts reduces a version string to a comparable sequence of integers.
//
// Strips a pacman epoch ("1:"), a pkgrel ("-2") and a tag's leading "v", then
// takes the leading dotted-numeric run. Deliberately tolerant: this decides
// which releases fall between installed and available, and an unparseable tag
// scheme should drop that one entry rather than abort the whole lookup.
func VParts(s string) []int {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ":"); i >= 0 && i < len(s) && !strings.Contains(s[:i], "-") {
		s = s[i+1:]
	}
	s = pkgrelRe.ReplaceAllString(s, "")
	s = strings.TrimLeft(s, "vV")
	m := tagRe.FindStringSubmatch(s)
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
