package sources

import (
	"strings"
	"time"

	"github.com/Sousf/patchlens/internal/model"
)

// flatpakColumns asks for a stable, tab-separated shape rather than the
// default human table, whose columns shift with terminal width.
const (
	listCols    = "--columns=application,version,branch"
	updatesCols = "--columns=application,branch,commit"
)

// installedFlatpaks maps "application/branch" to its installed version.
//
// Keyed on both because one application can be installed at several branches
// at once — org.freedesktop.Platform.GL.default is present here as both 25.08
// and 25.08-extra, and reporting them as one row would hide an update.
func installedFlatpaks() map[string]string {
	out := run(60*time.Second, "flatpak", "list", listCols)
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		res[f[0]+"/"+f[2]] = strings.TrimSpace(f[1])
	}
	return res
}

// FlatpakUpdates lists flatpak apps and runtimes with a newer commit available.
//
// Version strings are advisory here and frequently absent — runtimes such as
// the NVIDIA GL extension carry none at all. The commit is what actually
// identifies a build, so it stands in as the target version and gives the
// analysis cache something that changes when the update does.
func FlatpakUpdates() []model.Update {
	out := run(3*time.Minute, "flatpak", "remote-ls", "--updates", updatesCols)
	if strings.TrimSpace(out) == "" {
		return nil
	}
	installed := installedFlatpaks()

	var ups []model.Update
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		app, branch, commit := f[0], f[1], strings.TrimSpace(f[2])
		if len(commit) > 12 {
			commit = commit[:12]
		}
		name := app
		if branch != "" {
			name = app + "/" + branch
		}
		cur := installed[app+"/"+branch]
		if cur == "" {
			cur = "installed"
		}
		ups = append(ups, model.Update{
			Name:   name,
			Cur:    cur,
			New:    commit,
			Origin: model.Flatpak,
			URL:    "https://flathub.org/apps/" + app,
		})
	}
	return ups
}

// FlatpakAvailable reports whether flatpak is installed with anything in it.
func FlatpakAvailable() bool {
	return strings.TrimSpace(run(30*time.Second, "flatpak", "list", "--columns=application")) != ""
}
