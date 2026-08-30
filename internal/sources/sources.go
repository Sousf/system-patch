// Package sources enumerates what is pending and enriches it with what is
// known about it.
//
// Four independent inputs, merged into one slice of model.Update:
//
//	checkupdates  repo packages with a newer version   (pacman-contrib)
//	paru -Qua     AUR packages with a newer version    (paru)
//	arch-audit    Arch Security Tracker advisories     (repo packages only)
//	AUR RPC v5    upstream URL + current maintainer    (AUR packages only)
//
// The first two are the "what". The last two are the "why", and they cover
// disjoint halves of the system: the Security Tracker has no notion of an AUR
// package, so without the RPC half every AUR package would report a clean bill
// of health it was never actually checked for.
package sources

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sousf/system-patch/internal/adapters"
	"github.com/Sousf/system-patch/internal/cache"
	"github.com/Sousf/system-patch/internal/model"
)

const aurRPC = "https://aur.archlinux.org/rpc/v5/info"

// run executes a command and returns stdout. A missing binary yields "" rather
// than an error: a machine without paru still has repo updates worth showing.
func run(timeout time.Duration, name string, args ...string) string {
	if _, err := exec.LookPath(name); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

// parseUpgrades reads the "name old -> new" format both checkupdates and
// paru -Qua emit. Lines that do not match are warnings from the sync and are
// skipped rather than guessed at.
func parseUpgrades(out string, origin model.Origin) []model.Update {
	var ups []model.Update
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[2] == "->" {
			ups = append(ups, model.Update{Name: f[0], Cur: f[1], New: f[3], Origin: origin})
		}
	}
	return ups
}

// RepoUpdates lists repo packages with a newer version available.
//
// checkupdates syncs into a TEMPORARY database, so it never touches
// /var/lib/pacman/sync and cannot set up the `pacman -Sy` partial-upgrade
// footgun. That is the whole reason this is not `pacman -Sy && pacman -Qu`.
func RepoUpdates() []model.Update {
	return parseUpgrades(run(3*time.Minute, "checkupdates"), model.Repo)
}

// AURUpdates lists foreign packages with a newer version in the AUR.
func AURUpdates() []model.Update {
	return parseUpgrades(run(2*time.Minute, "paru", "-Qua"), model.AUR)
}

type advisory struct {
	Packages []string `json:"packages"`
	Severity string   `json:"severity"`
	Issues   []string `json:"issues"`
}

// Advisory is the merged Security Tracker view of one package.
type Advisory struct {
	CVEs     []string
	Severity string
}

// Unknown outranks the empty string so an advisory with no severity is still
// recorded as rated at all. It ranked 0, the same as absent, so the comparison
// below never stored it and the field stayed empty — which then rendered as
// "(severity )" in the brief and a dangling separator in the interface.
var sevRank = map[string]int{"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Unknown": 1}

// Advisories maps pkgname to its Security Tracker findings.
//
// Deliberately NOT `arch-audit -u`. That flag restricts output to advisories
// whose fix has already landed in the repos, which is right for a daily
// "you can act on this now" notification but wrong here: this tool answers
// "why is this update being pushed", and an advisory whose fix ships in the
// very update on screen is exactly what -u would filter out.
func Advisories() map[string]Advisory {
	out := run(60*time.Second, "arch-audit", "--json")
	if strings.TrimSpace(out) == "" {
		return nil
	}
	var advs []advisory
	if json.Unmarshal([]byte(out), &advs) != nil {
		return nil
	}
	byPkg := map[string]Advisory{}
	for _, a := range advs {
		for _, p := range a.Packages {
			e := byPkg[p]
			e.CVEs = append(e.CVEs, a.Issues...)
			sev := a.Severity
			if sev == "" {
				sev = "Unknown"
			}
			if sevRank[sev] > sevRank[e.Severity] {
				e.Severity = sev
			}
			byPkg[p] = e
		}
	}
	// Several advisories can name the same CVE. Order is preserved so the
	// highest-severity advisory's issues stay at the front.
	for p, e := range byPkg {
		seen := map[string]bool{}
		var uniq []string
		for _, c := range e.CVEs {
			if !seen[c] {
				seen[c] = true
				uniq = append(uniq, c)
			}
		}
		e.CVEs = uniq
		byPkg[p] = e
	}
	return byPkg
}

// RepoURLs maps pkgname to upstream URL, read from the local sync database.
//
// One `pacman -Si` call covering every package rather than one per package:
// -Si is a local read, so process spawn dominates at a few dozen packages.
func RepoURLs(names []string) map[string]string {
	if len(names) == 0 {
		return nil
	}
	out := run(60*time.Second, "pacman", append([]string{"-Si"}, names...)...)
	urls := map[string]string{}
	var cur string
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Name":
			cur = v
		case "URL":
			if cur != "" {
				urls[cur] = v
			}
		}
	}
	return urls
}

// AURMeta is the subset of AUR RPC fields this tool acts on.
type AURMeta struct {
	URL        string
	Maintainer string
	OutOfDate  bool
}

type aurResult struct {
	Name       string  `json:"Name"`
	URL        string  `json:"URL"`
	Maintainer *string `json:"Maintainer"`
	OutOfDate  *int64  `json:"OutOfDate"`
}

// AURInfo fetches URL and maintainer for every named package in one request.
//
// The AUR is donated infrastructure and rate-limits. `info` accepts repeated
// arg[] parameters, so every foreign package on a machine fits in a single
// call; looping per package would be both slower and rude.
func AURInfo(names []string) (map[string]AURMeta, error) {
	if len(names) == 0 {
		return nil, nil
	}
	q := make([]string, 0, len(names))
	for _, n := range names {
		q = append(q, "arg[]="+url.QueryEscape(n))
	}
	var resp struct {
		Results []aurResult `json:"results"`
	}
	if err := cache.FetchJSON(aurRPC+"?"+strings.Join(q, "&"), false, &resp); err != nil {
		return nil, err
	}
	meta := map[string]AURMeta{}
	for _, r := range resp.Results {
		m := AURMeta{URL: r.URL}
		// A null Maintainer is valid and meaningful: the package is orphaned
		// and therefore adoptable by anyone. Preserved as "" and reported, not
		// quietly treated as unchanged.
		if r.Maintainer != nil {
			m.Maintainer = *r.Maintainer
		}
		m.OutOfDate = r.OutOfDate != nil && *r.OutOfDate > 0
		meta[r.Name] = m
	}
	return meta, nil
}

// CheckProvenance compares current AUR maintainers against the stored baseline
// and returns pkgname -> previous maintainer for those that changed.
//
// Trust On First Use: the first run records who maintains what and reports
// nothing. Without that seeding step every package fires a "new maintainer"
// alert on day one and the signal is trained away before it ever means
// anything. It cannot catch a package that was already malicious when it was
// installed — only a change of hands, which is how the July 2026 AUR wave
// worked.
func CheckProvenance(meta map[string]AURMeta) map[string]string {
	path := filepath.Join(cache.StateDir(), "maintainers.json")
	var base map[string]string
	seeded := cache.ReadJSON(path, &base)

	now := map[string]string{}
	for k, v := range meta {
		now[k] = v.Maintainer
	}
	if !seeded || base == nil {
		_ = cache.WriteJSON(path, now)
		return nil
	}

	changed := map[string]string{}
	for n, m := range now {
		if prev, ok := base[n]; ok && prev != m {
			if prev == "" {
				prev = "(orphaned)"
			}
			changed[n] = prev
		}
	}
	// Merge rather than replace: a package that is temporarily absent from the
	// RPC response must not lose its recorded baseline.
	for k, v := range now {
		base[k] = v
	}
	_ = cache.WriteJSON(path, base)
	return changed
}

// Result is the outcome of a full enumeration.
type Result struct {
	Updates  []model.Update
	Warnings []string
	// Stamp is the pacman local-database mtime the result was gathered
	// against. Used to notice that packages have been installed or removed
	// since, which invalidates the whole enumeration.
	Stamp int64 `json:",omitempty"`
}

// localDBStamp is the mtime of pacman's local database, which changes on every
// install, upgrade and removal.
//
// A plain time-based TTL is not enough on its own: the one moment a stale
// answer is most misleading is straight after `pacman -Syu`, when the tool
// would still be listing updates that are no longer pending.
func localDBStamp() int64 {
	fi, err := os.Stat("/var/lib/pacman/local")
	if err != nil {
		return 0
	}
	return fi.ModTime().Unix()
}

// Load returns a recent enumeration, reusing a cached one when it is both
// young enough and gathered against the current package database.
//
// Collect runs checkupdates, which syncs a temporary database over the
// network. That is fine once per interactive session and far too expensive for
// a status-bar module polling every thirty seconds.
func Load(maxAge time.Duration) Result {
	var r Result
	if cache.Get("updates", maxAge, &r) && r.Stamp == localDBStamp() {
		return r
	}
	r = Collect()
	r.Stamp = localDBStamp()
	cache.Put("updates", r)
	return r
}

// rank orders origins by how little else is watching them.
func rank(o model.Origin) int {
	switch o {
	case model.AUR:
		return 0
	case model.Flatpak:
		return 1
	}
	return 2
}

// Collect gathers every pending update and enriches it.
func Collect() Result {
	// Every manager present on this machine enumerates concurrently, alongside
	// the security tracker and the news feed. Which managers those are is
	// decided at runtime, so this is not an Arch-only tool by construction.
	//
	// Concurrency is per manager, and one manager can still be two commands:
	// the pacman entry runs checkupdates and then paru -Qua, so on Arch the
	// cold path is their sum. RepoUpdates and AURUpdates run in parallel
	// inside that entry for the same reason the managers do.
	var (
		wg  sync.WaitGroup
		ups []model.Update
		adv map[string]Advisory
	)
	wg.Add(3)
	go func() { defer wg.Done(); ups = ManagerUpdates() }()
	go func() { defer wg.Done(); adv = Advisories() }()
	// Warmed here so the interface never fetches it. News is read from a render
	// function, and a miss there blocked the event loop on an HTTP round trip.
	go func() { defer wg.Done(); FetchNews() }()
	// Same reasoning: Unmanaged runs `npm ls -g`, which takes up to a couple of
	// seconds, and its one uncached call used to land on the UI goroutine the
	// first time the system row was rendered.
	wg.Add(1)
	go func() { defer wg.Done(); Unmanaged() }()
	wg.Wait()

	res := Result{Updates: ups}
	if len(res.Updates) == 0 {
		return res
	}

	// Grouped by origin rather than by position. The enumerators now run from
	// a runtime-detected registry, so which managers contributed rows — and in
	// what order — is not known at compile time.
	var repoNames, aurNames []string
	for _, u := range res.Updates {
		switch u.Origin {
		case model.Repo:
			repoNames = append(repoNames, u.Name)
		case model.AUR:
			aurNames = append(aurNames, u.Name)
		}
	}

	var (
		urls   map[string]string
		meta   map[string]AURMeta
		aurErr error
		wg2    sync.WaitGroup
	)
	wg2.Add(2)
	go func() { defer wg2.Done(); urls = RepoURLs(repoNames) }()
	go func() { defer wg2.Done(); meta, aurErr = AURInfo(aurNames) }()
	wg2.Wait()

	if aurErr != nil && len(aurNames) > 0 {
		res.Warnings = append(res.Warnings,
			"AUR metadata unavailable ("+aurErr.Error()+"); provenance not checked")
	}
	changed := CheckProvenance(meta)

	var aurRows []model.Update
	for i := range res.Updates {
		u := &res.Updates[i]
		switch u.Origin {
		case model.Repo:
			u.URL = urls[u.Name]
			if a, ok := adv[u.Name]; ok {
				u.CVEs, u.Severity = a.CVEs, a.Severity
			}
		case model.AUR:
			m := meta[u.Name]
			u.URL, u.Maintainer, u.OutOfDate = m.URL, m.Maintainer, m.OutOfDate
			if prev, ok := changed[u.Name]; ok {
				u.MaintainerWas = prev
			}
			aurRows = append(aurRows, *u)
		}
	}

	// AUR packages get their upstream security summary now rather than on
	// selection, because nothing else on this machine watches the AUR and an
	// unenriched AUR row would sort as routine. The repo half already has
	// Security Tracker data, so it stays lazy.
	//
	// Enriched through a name index rather than a slice range: the rows are no
	// longer grouped by origin in the underlying slice.
	adapters.Enrich(aurRows)
	byName := make(map[string]model.Update, len(aurRows))
	for _, u := range aurRows {
		byName[u.Name] = u
	}
	for i := range res.Updates {
		if e, ok := byName[res.Updates[i].Name]; ok && res.Updates[i].Origin == model.AUR {
			res.Updates[i].UpstreamCVEs = e.UpstreamCVEs
			res.Updates[i].UpstreamKind = e.UpstreamKind
		}
	}

	// Flagged first, then AUR ahead of repo. AUR outranks repo at equal
	// standing because nothing else on the machine is watching it.
	sort.SliceStable(res.Updates, func(i, j int) bool {
		a, b := res.Updates[i], res.Updates[j]
		if a.Flagged() != b.Flagged() {
			return a.Flagged()
		}
		// AUR first, then flatpak, then repo: both of the first two are
		// outside the Security Tracker's view, so nothing else on the machine
		// is watching them.
		if rank(a.Origin) != rank(b.Origin) {
			return rank(a.Origin) < rank(b.Origin)
		}
		return a.Name < b.Name
	})
	return res
}
