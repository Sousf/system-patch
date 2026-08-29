package sources

import (
	"encoding/xml"
	"strings"
	"time"

	"github.com/Sousf/patchlens/internal/cache"
	"github.com/Sousf/patchlens/internal/model"
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
func News(limit int) []NewsItem {
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
}

// Assess gathers the breakage picture for a single pending update.
func Assess(u model.Update) Breakage {
	b := Breakage{Deps: InstalledDeps(u.Name)}
	if u.Origin == model.Repo {
		b.Sonames = SonameChanges(b.Deps.Provides, CandidateProvides(u.Name))
	}
	foreign := Foreign()
	for _, r := range append(append([]string{}, b.Deps.RequiredBy...), b.Deps.OptionalFor...) {
		if foreign[r] {
			b.AtRiskBy = append(b.AtRiskBy, r)
		}
	}
	return b
}
