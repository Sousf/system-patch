// Package adapters turns "a new version exists" into "here is why it was pushed".
//
// Neither pacman nor the AUR carries a changelog. What they do carry is a
// pointer: the package's upstream URL. These adapters take that URL plus the
// installed/available version pair and read the actual release notes.
//
// Coverage is decided by host, so supporting a new forge means adding one
// function and one entry in the adapter list. Anything unmatched returns
// KindNone, which the UI renders as "no changelog source" rather than as an
// all-clear.
package adapters

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Sousf/system-patch/internal/cache"
	"github.com/Sousf/system-patch/internal/model"
)

var (
	cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	// Chrome writes severity immediately before the identifier:
	// "High CVE-2026-76033".
	chromeCVERe = regexp.MustCompile(`(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d{4,7})`)
	githubRe    = regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/#?]+)`)
	gitlabRe    = regexp.MustCompile(`^https?://gitlab\.com/([^#?]+)`)
	tagRe       = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+)\b`)
	fixesRe     = regexp.MustCompile(`includes\s+(\d+)\s+security fixes`)
	htmlRe      = regexp.MustCompile(`<[^>]+>`)
	securityRe  = regexp.MustCompile(`(?i)\b(securit|vulnerab|exploit|CWE-\d|overflow|` +
		`use[- ]after[- ]free|sanitiz|injection|traversal|privilege escalation|` +
		`\bRCE\b|denial of service)`)
)

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func classify(rels []model.Release) model.Kind {
	for _, r := range rels {
		if len(r.CVEs) > 0 {
			return model.KindSecurity
		}
	}
	for _, r := range rels {
		if securityRe.MatchString(r.Body) {
			// Prose that reads security-relevant but names no identifier.
			// Reported as suspected rather than confirmed, because the
			// difference decides "patch now" versus "patch on Sunday".
			return model.KindSuspected
		}
	}
	if len(rels) > 0 {
		return model.KindChangelog
	}
	return model.KindNone
}

func sortDesc(rels []model.Release) {
	sort.SliceStable(rels, func(i, j int) bool {
		return model.VCmp(model.VParts(rels[i].Version), model.VParts(rels[j].Version)) > 0
	})
}

// adapter returns nil when the URL is not its concern, so the caller can try
// the next one.
type adapter func(u model.Update) *model.Notes

// GitHub reads the Releases API.
func GitHub(u model.Update) *model.Notes {
	m := githubRe.FindStringSubmatch(u.URL)
	if m == nil {
		return nil
	}
	owner, repo := m[1], strings.TrimSuffix(m[2], ".git")
	src := "github.com/" + owner + "/" + repo

	var raw []struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		Body        string `json:"body"`
		PublishedAt string `json:"published_at"`
	}
	api := "https://api.github.com/repos/" + owner + "/" + repo + "/releases?per_page=40"
	if err := cache.FetchJSON(api, true, &raw); err != nil {
		return &model.Notes{Source: src, Kind: model.KindNone, Err: err.Error()}
	}

	var rels []model.Release
	for _, r := range raw {
		tag := r.TagName
		if tag == "" {
			tag = r.Name
		}
		if !model.InRange(tag, u.Cur, u.New) {
			continue
		}
		body := strings.TrimSpace(r.Body)
		rels = append(rels, model.Release{
			Version: tag,
			Date:    trunc(r.PublishedAt, 10),
			Body:    body,
			CVEs:    uniqSorted(cveRe.FindAllString(body, -1)),
		})
	}
	sortDesc(rels)
	n := &model.Notes{Source: src, Kind: classify(rels), Releases: rels}
	if len(rels) == 0 {
		// Plenty of projects tag without ever cutting a GitHub Release. Say so
		// explicitly; an empty pane otherwise reads as "nothing changed".
		n.Err = "no GitHub releases in this version range"
	}
	return n
}

// GitLab reads the Releases API.
func GitLab(u model.Update) *model.Notes {
	m := gitlabRe.FindStringSubmatch(u.URL)
	if m == nil {
		return nil
	}
	path := strings.TrimSuffix(strings.TrimRight(m[1], "/"), ".git")
	src := "gitlab.com/" + path

	var raw []struct {
		TagName     string `json:"tag_name"`
		Description string `json:"description"`
		ReleasedAt  string `json:"released_at"`
	}
	api := "https://gitlab.com/api/v4/projects/" + url.PathEscape(path) + "/releases"
	if err := cache.FetchJSON(api, false, &raw); err != nil {
		return &model.Notes{Source: src, Kind: model.KindNone, Err: err.Error()}
	}

	var rels []model.Release
	for _, r := range raw {
		if !model.InRange(r.TagName, u.Cur, u.New) {
			continue
		}
		body := strings.TrimSpace(r.Description)
		rels = append(rels, model.Release{
			Version: r.TagName,
			Date:    trunc(r.ReleasedAt, 10),
			Body:    body,
			CVEs:    uniqSorted(cveRe.FindAllString(body, -1)),
		})
	}
	sortDesc(rels)
	n := &model.Notes{Source: src, Kind: classify(rels), Releases: rels}
	if len(rels) == 0 {
		n.Err = "no GitLab releases in this version range"
	}
	return n
}

const chromeFeed = "https://chromereleases.googleblog.com/feeds/posts/default" +
	"?alt=json&max-results=80"

// Chrome reads Google's release blog.
//
// Chrome ships no changelog through the AUR, but Google publishes one. Chrome
// Releases is a Blogger blog, so alt=json makes it serve its Atom feed as JSON
// — no XML parser, no API key. The feed interleaves ChromeOS, Android and Beta
// posts, hence the title filter: only "Stable Channel Update for Desktop"
// describes the package installed here.
func Chrome(u model.Update) *model.Notes {
	if !strings.Contains(strings.ToLower(u.URL), "google.com/chrome") {
		return nil
	}
	src := "chromereleases.googleblog.com"
	var feed struct {
		Feed struct {
			Entry []struct {
				Title struct {
					T string `json:"$t"`
				} `json:"title"`
				Content struct {
					T string `json:"$t"`
				} `json:"content"`
				Published struct {
					T string `json:"$t"`
				} `json:"published"`
			} `json:"entry"`
		} `json:"feed"`
	}
	if err := cache.FetchJSON(chromeFeed, false, &feed); err != nil {
		return &model.Notes{Source: src, Kind: model.KindNone, Err: err.Error()}
	}

	var rels []model.Release
	for _, e := range feed.Feed.Entry {
		if !strings.Contains(e.Title.T, "Stable Channel Update for Desktop") {
			continue
		}
		// The second replacement swaps U+00A0 for a plain space. Blogger's editor
		// litters these through the post, and one sitting between a severity
		// word and its identifier is enough to break the pairing regex.
		text := strings.ReplaceAll(htmlRe.ReplaceAllString(e.Content.T, " "), " ", " ")
		vm := tagRe.FindStringSubmatch(text)
		if vm == nil || !model.InRange(vm[1], u.Cur, u.New) {
			continue
		}
		sev := map[string]string{}
		var cves []string
		for _, p := range chromeCVERe.FindAllStringSubmatch(text, -1) {
			sev[p[2]] = p[1]
			cves = append(cves, p[2])
		}
		// The headline count Google states is authoritative and can exceed the
		// itemised list, because bugs found by internal fuzzers are aggregated
		// rather than enumerated.
		body := ""
		if f := fixesRe.FindStringSubmatch(text); f != nil {
			body = f[1] + " security fixes"
		}
		rels = append(rels, model.Release{
			Version:    vm[1],
			Date:       trunc(e.Published.T, 10),
			Body:       body,
			CVEs:       uniqSorted(cves),
			Severities: sev,
		})
	}
	sortDesc(rels)
	n := &model.Notes{Source: src, Kind: classify(rels), Releases: rels}
	if len(rels) == 0 {
		n.Err = "no desktop stable posts in this version range"
	}
	return n
}

// Order matters: Chrome is tried first because google.com/chrome matches
// neither forge, and a future Chromium-on-GitHub URL should still prefer the
// feed that carries per-CVE severities.
var all = []adapter{Chrome, GitHub, GitLab}

// For returns release notes for one update, cached on the version pair.
//
// Keyed by name@cur..new rather than by time: the answer to "what is in 2.17.0
// that was not in 2.16.2" does not change, so a hit stays valid until one of
// the versions moves.
func For(u model.Update, refresh bool) model.Notes {
	key := "notes-" + u.Name + "@" + u.Cur + ".." + u.New
	var n model.Notes
	if !refresh && cache.Get(key, cache.NotesTTL, &n) {
		return n
	}

	var got *model.Notes
	if u.URL != "" {
		for _, fn := range all {
			if got = fn(u); got != nil {
				break
			}
		}
	}
	if got == nil {
		src := u.URL
		if src == "" {
			src = "(no upstream URL)"
		}
		got = &model.Notes{Source: src, Kind: model.KindNone,
			Err: "no changelog adapter for this host"}
	}

	// Repo packages inherit the Security Tracker's CVEs even when upstream
	// published nothing. For those, the advisory *is* the reason for the push.
	if len(u.CVEs) > 0 && (got.Kind == model.KindNone || got.Kind == model.KindChangelog) {
		got.Kind = model.KindSecurity
	}

	cache.Put(key, got)
	return *got
}

// Enrich fills in each update's upstream security summary, in place.
//
// Run over AUR packages at enumeration time rather than lazily, because the
// AUR is the half of the system nothing else watches: without this pass an AUR
// package carrying hundreds of vendor-disclosed CVEs sorts below a routine
// repo bump and reads as unremarkable. Repo packages already carry Security
// Tracker data, so they are enriched lazily on selection instead — forty extra
// HTTP calls at startup is not worth the same signal twice.
//
// Bounded concurrency: these are independent network calls, but the AUR and
// the forges are shared infrastructure and deserve a ceiling.
func Enrich(ups []model.Update) {
	const workers = 6
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i := range ups {
		if ups[i].URL == "" {
			continue
		}
		wg.Add(1)
		go func(u *model.Update) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			n := For(*u, false)
			seen := map[string]bool{}
			for _, r := range n.Releases {
				for _, c := range r.CVEs {
					seen[c] = true
				}
			}
			u.UpstreamCVEs = len(seen)
			u.UpstreamKind = n.Kind
		}(&ups[i])
	}
	wg.Wait()
}

var pkgrelRe = regexp.MustCompile(`-\d+$`)

// gitTag converts a pacman version into the tag upstream probably used.
//
// A pacman version is not a git ref. "1.23.1-4" carries an Arch pkgrel that no
// upstream tag has ever contained, and most projects prefix tags with "v". A
// compare URL built from the raw versions simply 404s — observed on libheif,
// where the analysis had to notice the dead link and reconstruct the real tags
// itself before it could read anything.
//
// The prefix is copied from a tag actually seen in this project's releases
// rather than guessed, falling back to a bare version when none were fetched.
func gitTag(v string, n model.Notes) string {
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:] // epoch
	}
	v = pkgrelRe.ReplaceAllString(v, "")
	for _, r := range n.Releases {
		if strings.HasPrefix(r.Version, "v") {
			return "v" + v
		}
		break
	}
	return v
}

// CompareURL is a machine-fetchable diff of exactly what this update changes.
//
// This is what makes source analysis possible rather than speculative: the
// agent reads the code that changed, not somebody's summary of it.
func CompareURL(u model.Update, n model.Notes) string {
	from, to := gitTag(u.Cur, n), gitTag(u.New, n)
	if m := githubRe.FindStringSubmatch(u.URL); m != nil {
		repo := strings.TrimSuffix(m[2], ".git")
		return "https://github.com/" + m[1] + "/" + repo + "/compare/" + from + "..." + to
	}
	if m := gitlabRe.FindStringSubmatch(u.URL); m != nil {
		path := strings.TrimSuffix(strings.TrimRight(m[1], "/"), ".git")
		return "https://gitlab.com/" + path + "/-/compare/" + from + "..." + to
	}
	return ""
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
