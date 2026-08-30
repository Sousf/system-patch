package sources

import (
	"os"
	"strings"
	"sync"
)

// Family is the packaging tradition a machine belongs to.
//
// Not the distribution. Ubuntu, Debian and Mint answer the breakage question
// identically because they share dpkg and apt, and the analysis only ever cares
// about that shared part.
type Family string

const (
	Arch    Family = "arch"
	Debian  Family = "debian"
	Fedora  Family = "fedora"
	SUSE    Family = "suse"
	Alpine  Family = "alpine"
	Void    Family = "void"
	Gentoo  Family = "gentoo"
	Unknown Family = "unknown"
)

// HostInfo is everything the analysis needs to know about the machine it is
// describing, so that no brief has to assume a distribution.
//
// The Arch-only build shipped a prompt that named pacman, the AUR, .pacnew
// files and the Arch news feed. Run on Ubuntu it produced a report that opened
// by saying the framing was wrong, and refused the task rather than inventing
// pacman output. That refusal was correct, and it is what this type exists to
// prevent.
type HostInfo struct {
	Family Family
	// Pretty is the PRETTY_NAME from os-release, e.g. "Ubuntu 24.04.3 LTS".
	Pretty string
	// Distro is the os-release ID, e.g. "ubuntu". Kept separate from Family
	// because a brief should name the actual system, not its tradition.
	Distro string

	// DBNote tells the agent how to read the local package database without
	// invoking the package manager, which is denied.
	DBNote string
	// InspectTools are read-only Bash tools worth pre-approving here. Granting
	// pactree on Ubuntu is noise; granting dpkg-query is the difference between
	// an answer and a guess.
	InspectTools []string
	// ManagerBins are the commands that can change this system. Denied to the
	// agent, because a tool that answers "should I install this?" must not be
	// able to install it.
	ManagerBins []string

	// ConfigConvention names what the upgrade leaves behind for the admin to
	// merge: .pacnew on Arch, prompts and .dpkg-dist on Debian, .rpmnew on
	// Fedora. Empty when the family has no such convention.
	ConfigConvention string
	// ForeignNote describes packages the upgrade does not rebuild, which is
	// where breakage actually lands. Empty where the archive is self-consistent
	// and the solver handles it.
	ForeignNote string
	// ArchNews reports whether the Arch announcement feed applies here.
	ArchNews bool
	// KernelNames matches this family's kernel packages. A kernel update
	// replaces the running kernel's modules on disk, which is the one delayed
	// failure worth naming, and the package is called linux on Arch, kernel on
	// Fedora and kernel-default on openSUSE.
	KernelNames []string
}

// IsKernel reports whether a package name is one of this family's kernels.
func (h HostInfo) IsKernel(name string) bool {
	for _, k := range h.KernelNames {
		if name == k || strings.HasPrefix(name, k+"-") {
			return true
		}
	}
	return false
}

// allManagerBins is every command known to install or upgrade software on any
// supported system. Whichever of these exist here are denied to the agent,
// independent of the detected family.
//
// Deliberately wider than the registry in managers.go: that table lists what
// this tool can drive, and this one lists what an analysis must not be able to
// run. A manager too obscure to drive can still install a package.
var allManagerBins = []string{
	"pacman", "paru", "yay", "pikaur", "makepkg", "pacman-key",
	"apt", "apt-get", "aptitude", "dpkg", "dpkg-reconfigure",
	"dnf", "dnf5", "yum", "rpm", "rpm-ostree", "microdnf",
	"zypper", "apk", "xbps-install", "xbps-remove", "xbps-pkgdb",
	"emerge", "ebuild", "quickpkg",
	"flatpak", "snap", "brew", "nix", "nix-env", "guix",
	"pipx", "pip", "pip3", "npm", "cargo", "rustup", "mise", "gem", "go",
}

var (
	hostOnce sync.Once
	hostInfo HostInfo
)

// Host describes the running system. Resolved once per process.
func Host() HostInfo {
	hostOnce.Do(func() { hostInfo = detectHost() })
	return hostInfo
}

// osRelease parses /etc/os-release into its key/value pairs.
func osRelease() map[string]string {
	out := map[string]string{}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			out[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
		break
	}
	return out
}

// detectHost reads os-release first and falls back to which binaries exist.
//
// ID_LIKE carries the derivatives: Ubuntu declares "debian", Rocky declares
// "rhel fedora", so one table entry covers a family without naming every
// downstream. A machine that answers neither is still usable — the analysis
// simply says it cannot read the local database, which is true.
func detectHost() HostInfo {
	// SYSTEM_PATCH_DISTRO forces the family, so a brief for another system can
	// be read with `prompt` from the machine you have rather than the one it
	// describes.
	//
	// ID_LIKE is carried too. Without it the override reached only the literal
	// IDs in the table, so the derivatives it exists to preview — linuxmint,
	// rocky, endeavouros, opensuse-tumbleweed — all landed on Unknown, which
	// is every case worth previewing.
	if id := os.Getenv("SYSTEM_PATCH_DISTRO"); id != "" {
		rel := map[string]string{"ID": id}
		if like := derivativeLike(id); like != "" {
			rel["ID_LIKE"] = like
		}
		return hostFrom(rel, has)
	}
	return hostFrom(osRelease(), has)
}

// derivativeLike supplies the ID_LIKE a real machine would publish, for the
// override, which has only a name to go on.
//
// Only needed for IDs the table does not match directly. A real system is
// never read through this: it publishes its own ID_LIKE.
func derivativeLike(id string) string {
	switch id {
	case "linuxmint", "pop", "elementary", "zorin", "raspbian", "kali", "devuan":
		return "debian ubuntu"
	case "rocky", "almalinux", "ol", "amzn":
		return "rhel fedora centos"
	case "endeavouros", "manjaro", "cachyos", "garuda":
		return "arch"
	case "opensuse-tumbleweed", "opensuse-leap", "opensuse-microos":
		return "opensuse suse"
	}
	return ""
}

// hostFrom builds the description from parsed os-release fields.
//
// Split from detectHost so the family table can be exercised against every
// distribution's real os-release without that distribution: the fallbacks are
// the interesting part, and they only fire on machines this one is not.
func hostFrom(rel map[string]string, hasBin func(string) bool) HostInfo {
	id := rel["ID"]
	like := rel["ID_LIKE"]
	pretty := rel["PRETTY_NAME"]
	if pretty == "" {
		pretty = rel["NAME"]
	}

	is := func(names ...string) bool {
		for _, n := range names {
			if id == n {
				return true
			}
			for _, l := range strings.Fields(like) {
				if l == n {
					return true
				}
			}
		}
		return false
	}

	h := HostInfo{Family: Unknown, Distro: id, Pretty: pretty}
	switch {
	case is("arch", "archlinux") || (id == "" && hasBin("pacman")):
		h.Family = Arch
	case is("debian", "ubuntu") || (id == "" && hasBin("dpkg")):
		h.Family = Debian
	case is("fedora", "rhel", "centos") || (id == "" && hasBin("rpm") && hasBin("dnf")):
		h.Family = Fedora
	case is("opensuse", "suse", "sles"):
		h.Family = SUSE
	case is("alpine"):
		h.Family = Alpine
	case is("void"):
		h.Family = Void
	case is("gentoo"):
		h.Family = Gentoo
	}
	if h.Pretty == "" {
		h.Pretty = title(id)
	}
	if h.Pretty == "" {
		h.Pretty = string(h.Family)
	}

	switch h.Family {
	case Arch:
		h.KernelNames = []string{"linux"}
		h.DBNote = `  /var/lib/pacman/local/<name>-<version>/desc   installed packages
  /var/lib/pacman/sync/*.db                     repository metadata (tar)

pactree, uname and expac do work if you need them.`
		h.InspectTools = []string{"Bash(pactree:*)", "Bash(expac:*)"}
		h.ManagerBins = []string{"pacman", "paru", "yay", "makepkg", "pacman-key"}
		h.ConfigConvention = ".pacnew files left beside any config the upgrade could not " +
			"replace, which take effect only once merged"
		h.ForeignNote = "AUR packages are built locally and are not rebuilt by an upgrade, " +
			"so a repository library moving its soname breaks them until you rebuild"
		h.ArchNews = true

	case Debian:
		h.KernelNames = []string{"linux-image", "linux-generic", "linux-headers"}
		h.DBNote = `  /var/lib/dpkg/status                          installed packages and versions
  /var/lib/apt/lists/*Packages                  archive metadata

dpkg-query and apt-cache are read-only and available to you: dpkg-query -l,
dpkg-query -W, apt-cache policy, apt-cache rdepends, apt-cache show. uname is
available. dpkg and apt are blocked, because both can also install.`
		h.InspectTools = []string{"Bash(dpkg-query:*)", "Bash(apt-cache:*)"}
		h.ManagerBins = []string{"apt", "apt-get", "aptitude", "dpkg", "dpkg-reconfigure"}
		h.ConfigConvention = "modified config files prompt on upgrade, or are left as " +
			".dpkg-dist and .dpkg-new beside the original when running non-interactively"
		h.ForeignNote = "packages from third-party repositories and PPAs, which are not " +
			"upgraded in step with the distribution archive and are where version skew lands"

	case Fedora:
		h.KernelNames = []string{"kernel"}
		h.DBNote = `  /var/lib/rpm                                  the rpm database

rpmquery and repoquery are read-only and available to you: rpmquery -a,
rpmquery --whatrequires, rpmquery --provides, repoquery --requires. uname is
available. rpm and dnf are blocked, because both can also install.`
		h.InspectTools = []string{"Bash(rpmquery:*)", "Bash(repoquery:*)"}
		h.ManagerBins = []string{"dnf", "yum", "rpm", "rpm-ostree", "microdnf"}
		h.ConfigConvention = ".rpmnew and .rpmsave files left beside configs the upgrade " +
			"could not merge"
		h.ForeignNote = "packages from COPR or third-party repositories, which are not " +
			"rebuilt in step with the distribution"

	case SUSE:
		h.KernelNames = []string{"kernel-default", "kernel"}
		h.DBNote = `  /var/lib/rpm                                  the rpm database

rpmquery is read-only and available to you: rpmquery -a, rpmquery --provides.
uname is available. rpm and zypper are blocked, because both can also install.`
		h.InspectTools = []string{"Bash(rpmquery:*)"}
		h.ManagerBins = []string{"zypper", "rpm"}
		h.ConfigConvention = ".rpmnew and .rpmsave files left beside configs the upgrade " +
			"could not merge"

	case Alpine:
		h.KernelNames = []string{"linux-lts", "linux-virt"}
		h.DBNote = `  /lib/apk/db/installed                         installed packages

That file is plain text, one stanza per package: read it directly. uname is
available. apk is blocked, because it can also install.`
		h.InspectTools = nil
		h.ManagerBins = []string{"apk"}
		h.ConfigConvention = ".apk-new files left beside configs the upgrade could not replace"

	case Void:
		h.KernelNames = []string{"linux"}
		h.DBNote = `  /var/db/xbps                                  installed packages

xbps-query is read-only and works. uname is available.`
		h.InspectTools = []string{"Bash(xbps-query:*)"}
		h.ManagerBins = []string{"xbps-install", "xbps-remove", "xbps-pkgdb"}
		h.ConfigConvention = ".new-<version> files left beside configs the upgrade could not replace"

	case Gentoo:
		h.KernelNames = []string{"gentoo-sources", "gentoo-kernel"}
		h.DBNote = `  /var/db/pkg/<category>/<name>-<version>        installed packages

equery and qlist are read-only and work if portage-utils is installed. uname
is available.`
		h.InspectTools = []string{"Bash(equery:*)", "Bash(qlist:*)", "Bash(qdepends:*)"}
		h.ManagerBins = []string{"emerge", "ebuild", "quickpkg"}
		h.ConfigConvention = "._cfg0000_ files left for dispatch-conf or etc-update to merge"
		h.ForeignNote = "packages built from local overlays, which are not rebuilt in step " +
			"with the main tree"

	default:
		h.DBNote = "The package database layout here is not known to this tool. Do not " +
			"guess at paths; say what you could not check."
	}

	// Every manager actually on this machine is denied, whatever the detected
	// family says.
	//
	// The family list alone was not enough, twice over. An Unknown family
	// declared no managers at all, so nothing was denied while the brief still
	// told the agent its package manager was blocked. And SYSTEM_PATCH_DISTRO
	// selects a family without changing the machine, so previewing an Ubuntu
	// brief from an Arch box left pacman, paru and makepkg available to a run
	// executing on that Arch box. The deny list has to describe the host, not
	// the subject of the report.
	seen := map[string]bool{}
	for _, c := range h.ManagerBins {
		seen[c] = true
	}
	for _, c := range allManagerBins {
		if !seen[c] && hasBin(c) {
			seen[c] = true
			h.ManagerBins = append(h.ManagerBins, c)
		}
	}
	return h
}

// title capitalises an os-release ID for prose, so a brief opens with "Ubuntu"
// rather than "ubuntu" when no PRETTY_NAME was published.
func title(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Describe names the running system for the opening line of a brief.
func (h HostInfo) Describe() string {
	if h.Pretty != "" && h.Pretty != string(h.Family) {
		return h.Pretty
	}
	if h.Distro != "" {
		return h.Distro
	}
	return "this Linux system"
}

// DeniedTools renders the manager binaries as Claude Code deny patterns.
//
// Both spellings of each pattern, for the reason the package-level list gives:
// which form the CLI honours is not something to assume.
func (h HostInfo) DeniedTools() []string {
	var out []string
	for _, c := range h.ManagerBins {
		out = append(out, "Bash("+c+":*)", "Bash("+c+" *)")
	}
	return out
}
