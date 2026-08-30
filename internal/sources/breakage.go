package sources

import (
	"encoding/xml"
	"strings"
	"time"

	"github.com/Sousf/system-patch/internal/cache"
	"github.com/Sousf/system-patch/internal/model"
)

// Deps is what the local database knows about a package's place in the graph.
type Deps struct {
	// RequiredBy are installed packages that will not work without this one.
	RequiredBy []string
	// OptionalFor are installed packages that use it when present. They keep
	// working without it, but usually lose a feature.
	OptionalFor []string
	// Provides holds the versioned sonames this package exports, e.g.
	// "libheif.so=1-64". This is the field breakage actually turns on.
	Provides []string
}

// parseList reads pacman's "None" or space-separated list convention.
func parseList(v string) []string {
	if v == "" || v == "None" {
		return nil
	}
	return strings.Fields(v)
}

func parseInfo(out string) map[string]Deps {
	res := map[string]Deps{}
	var cur string
	var d Deps
	flush := func() {
		if cur != "" {
			res[cur] = d
		}
		cur, d = "", Deps{}
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Name":
			flush()
			cur = v
		case "Required By":
			d.RequiredBy = parseList(v)
		case "Optional For":
			d.OptionalFor = parseList(v)
		case "Provides":
			d.Provides = parseList(v)
		}
	}
	flush()
	return res
}

// InstalledDeps reads the local database for one installed package.
func InstalledDeps(name string) Deps {
	return parseInfo(run(30*time.Second, "pacman", "-Qi", name))[name]
}

// CandidateProvides is what the incoming version will export.
//
// Only meaningful for repo packages: an AUR package has not been built yet, so
// nothing can know its sonames until it is.
func CandidateProvides(name string) []string {
	return parseInfo(run(30*time.Second, "pacman", "-Si", name))[name].Provides
}

// soname reduces "libheif.so=1-64" to "libheif.so=1" — the part whose change
// breaks a consumer. The trailing architecture tag is noise here.
func soname(p string) (lib, ver string, ok bool) {
	lib, rest, ok := strings.Cut(p, "=")
	if !ok {
		return "", "", false
	}
	ver, _, _ = strings.Cut(rest, "-")
	return lib, ver, true
}

// SonameChanges compares what a package exports now against what the update
// will export, returning human-readable descriptions of every break.
//
// This is the mechanism behind most "updating X broke Y" on Arch. When a
// library's soname goes from libfoo.so.1 to libfoo.so.2, everything linked
// against the old one stops loading until it is rebuilt. Repository packages
// are rebuilt together so the repos stay self-consistent; AUR packages are
// not, which is why the casualties are almost always the foreign ones.
//
// Computed here rather than left to the agent: it is an exact comparison of
// two lists, and an exact answer is worth more than a confident guess.
func SonameChanges(before, after []string) []string {
	old := map[string]string{}
	for _, p := range before {
		if lib, ver, ok := soname(p); ok {
			old[lib] = ver
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range after {
		lib, ver, ok := soname(p)
		if !ok {
			continue
		}
		seen[lib] = true
		if prev, had := old[lib]; had && prev != ver {
			out = append(out, lib+": "+prev+" -> "+ver)
		}
	}
	for lib, ver := range old {
		if !seen[lib] {
			out = append(out, lib+": "+ver+" -> dropped")
		}
	}
	return out
}

// Foreign is the set of installed packages that came from the AUR.
//
// Used to separate reverse dependencies that a system upgrade will rebuild for
// you from the ones you will have to rebuild yourself.
func Foreign() map[string]bool {
	out := run(60*time.Second, "pacman", "-Qmq")
	set := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			set[l] = true
		}
	}
	return set
}

// NewsItem is one post from the Arch front page.
type NewsItem struct {
	Title   string `json:"title"`
	Date    string `json:"date"`
	Link    string `json:"link"`
	Summary string `json:"summary"`
}

// RequiresIntervention reports whether the post announces a manual step.
//
// These are the posts that turn an ordinary upgrade into a broken system when
// skipped, and the reason Arch expects its news to be read before upgrading.
func (n NewsItem) RequiresIntervention() bool {
	t := strings.ToLower(n.Title + " " + n.Summary)
	for _, s := range []string{"manual intervention", "requires action", "manual action"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

const newsFeed = "https://archlinux.org/feeds/news/"

var tagRe = strings.NewReplacer("\n", " ", "\t", " ")

// News fetches recent Arch announcements, most recent first.
//
// Cached for an hour: the feed changes a few times a month, and a system
// upgrade analysis should not re-fetch it on every run.
//
// Returns nothing off Arch. The feed announces manual steps for one
// distribution, and the callers — the interface banner and the system brief —
// both treat an empty result as "no announcements to check", which is the
// correct reading elsewhere. Debian and Fedora publish nothing equivalent:
// their release notes are per-release, not per-upgrade.
func News(limit int) []NewsItem {
	if !Host().ArchNews {
		return nil
	}
	var items []NewsItem
	if cache.Get("arch-news", time.Hour, &items) && len(items) > 0 {
		return trim(items, limit)
	}

	body, err := cache.FetchText(newsFeed)
	if err != nil {
		return nil
	}
	var doc struct {
		Items []struct {
			Title string `xml:"title"`
			Link  string `xml:"link"`
			Date  string `xml:"pubDate"`
			Desc  string `xml:"description"`
		} `xml:"channel>item"`
	}
	if xml.Unmarshal([]byte(body), &doc) != nil {
		return nil
	}
	for _, it := range doc.Items {
		items = append(items, NewsItem{
			Title:   strings.TrimSpace(it.Title),
			Date:    strings.TrimSpace(it.Date),
			Link:    strings.TrimSpace(it.Link),
			Summary: strings.TrimSpace(tagRe.Replace(stripTags(it.Desc))),
		})
	}
	if len(items) > 0 {
		cache.Put("arch-news", items)
	}
	return trim(items, limit)
}

func trim(items []NewsItem, limit int) []NewsItem {
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

// stripTags removes the HTML the feed embeds in each description.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// Breakage is everything known about what one update might disturb.
type Breakage struct {
	Deps     Deps
	Sonames  []string
	AtRiskBy []string // reverse dependencies that came from the AUR
	// Source names the database this came from: "pacman", "dpkg", or "" when
	// the running system has none this tool can read. The distinction matters
	// more than it looks: an empty Deps means "nothing depends on it" only if
	// something was actually read, and reporting the two the same way is how a
	// brief ends up asserting a fact it never checked.
	Source string
}

// Known reports whether the dependency graph was actually read.
func (b Breakage) Known() bool { return b.Source != "" }

// Assess gathers the breakage picture for a single pending update.
//
// Dispatched on the host's packaging family. Only the pacman path can answer
// the soname question, because only there does a library keep one package name
// across a soname change. dpkg and rpm encode the soname into the package name,
// so the archive carries both versions and the solver refuses the partial
// upgrade that would break — a different, and largely already-answered,
// question.
func Assess(u model.Update) Breakage {
	// Only the system package manager's own rows are in its database. A
	// flatpak ref or a snap is not, so querying pacman for one returns nothing
	// and that nothing means "wrong database", not "nothing depends on it".
	// Reported as fact it became exactly the fabrication this type guards
	// against, on the maintainer's own machine, for every flatpak row.
	if !u.Origin.System() {
		return Breakage{}
	}

	switch Host().Family {
	case Arch:
		deps, ok := archDeps(u.Name)
		if !ok {
			return Breakage{}
		}
		b := Breakage{Deps: deps, Source: "pacman"}
		if u.Origin == model.Repo {
			b.Sonames = SonameChanges(b.Deps.Provides, CandidateProvides(u.Name))
		}
		// Only worth the extra process when there is something to classify.
		if len(b.Deps.RequiredBy) > 0 || len(b.Deps.OptionalFor) > 0 {
			foreign := Foreign()
			for _, r := range append(append([]string{}, b.Deps.RequiredBy...), b.Deps.OptionalFor...) {
				if foreign[r] {
					b.AtRiskBy = append(b.AtRiskBy, r)
				}
			}
		}
		return b
	case Debian:
		if d, ok := debDeps(u.Name); ok {
			return Breakage{Deps: d, Source: "dpkg"}
		}
	}
	return Breakage{}
}

// archDeps reads one package's entry, reporting whether pacman knew it at all.
//
// ok distinguishes "queried, and nothing depends on it" from "the query
// returned nothing", which read the same way before and must not.
func archDeps(name string) (Deps, bool) {
	out := run(30*time.Second, "pacman", "-Qi", name)
	if strings.TrimSpace(out) == "" {
		return Deps{}, false
	}
	d, ok := parseInfo(out)[name]
	return d, ok
}

// debDeps reads reverse dependencies from the apt cache.
//
// The narrow invocation excludes Recommends and Suggests, which describe
// packages that keep working without this one and are the wrong list for a
// breakage question. It is tried first and the plain form second, because
// those flags are spelled with capitals in apt's own documentation and a
// rejected flag yields no output at all.
//
// ok is false when nothing could be read, and that distinction is the point:
// an empty result reported as fact becomes "nothing depends on it", which is
// the fabrication this whole path exists to avoid.
func debDeps(name string) (Deps, bool) {
	if !has("apt-cache") {
		return Deps{}, false
	}
	for _, args := range [][]string{
		{"rdepends", "--installed", "--no-Recommends", "--no-Suggests",
			"--no-Conflicts", "--no-Breaks", "--no-Replaces", "--no-Enhances", name},
		{"rdepends", "--installed", name},
	} {
		out := run(30*time.Second, "apt-cache", args...)
		if strings.TrimSpace(out) == "" {
			continue
		}
		var d Deps
		seen := map[string]bool{name: true}
		for _, line := range strings.Split(out, "\n") {
			// Data lines are indented; the package name and the "Reverse
			// Depends:" header are not. Alternatives carry a leading pipe.
			if line == "" || !strings.HasPrefix(line, " ") {
				continue
			}
			dep := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "|"))
			if dep == "" || seen[dep] {
				continue
			}
			seen[dep] = true
			d.RequiredBy = append(d.RequiredBy, dep)
		}
		// Output that parsed to nothing still proves the query ran: the package
		// is real and genuinely has no installed reverse dependencies.
		return d, true
	}
	return Deps{}, false
}
