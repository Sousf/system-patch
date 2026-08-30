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
	// describes. Detection is otherwise unconditional; this only overrides the
	// os-release ID, and every derived fact still comes from the same table.
	if id := os.Getenv("SYSTEM_PATCH_DISTRO"); id != "" {
		return hostFrom(map[string]string{"ID": id}, has)
	}
	return hostFrom(osRelease(), has)
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
		h.DBNote = `  /var/lib/dpkg/status                          installed packages and versions
  /var/lib/apt/lists/*Packages                  archive metadata

dpkg-query, dpkg -l, apt-cache policy, apt-cache rdepends and apt-cache show
are read-only and work. So does apt list --upgradable. uname is available.`
		h.InspectTools = []string{
			"Bash(dpkg:*)", "Bash(dpkg-query:*)", "Bash(apt-cache:*)", "Bash(apt-mark:*)",
		}
		h.ManagerBins = []string{"apt", "apt-get", "aptitude", "dpkg", "dpkg-reconfigure", "snap"}
		h.ConfigConvention = "modified config files prompt on upgrade, or are left as " +
			".dpkg-dist and .dpkg-new beside the original when running non-interactively"
		h.ForeignNote = "packages from third-party repositories and PPAs, which are not " +
			"upgraded in step with the distribution archive and are where version skew lands"

	case Fedora:
		h.DBNote = `  /var/lib/rpm                                  the rpm database

rpm -q, rpm -qa, rpm -q --whatrequires, rpm -q --provides and dnf repoquery
are read-only and work. uname is available.`
		h.InspectTools = []string{"Bash(rpm:*)", "Bash(repoquery:*)", "Bash(rpmquery:*)"}
		h.ManagerBins = []string{"dnf", "yum", "rpm", "rpm-ostree", "microdnf"}
		h.ConfigConvention = ".rpmnew and .rpmsave files left beside configs the upgrade " +
			"could not merge"
		h.ForeignNote = "packages from COPR or third-party repositories, which are not " +
			"rebuilt in step with the distribution"

	case SUSE:
		h.DBNote = `  /var/lib/rpm                                  the rpm database

rpm -q and zypper info are read-only and work. uname is available.`
		h.InspectTools = []string{"Bash(rpm:*)"}
		h.ManagerBins = []string{"zypper", "rpm"}
		h.ConfigConvention = ".rpmnew and .rpmsave files left beside configs the upgrade " +
			"could not merge"

	case Alpine:
		h.DBNote = `  /lib/apk/db/installed                         installed packages

apk info and apk list are read-only and work. uname is available.`
		h.InspectTools = []string{"Bash(apk:*)"}
		h.ManagerBins = []string{"apk"}
		h.ConfigConvention = ".apk-new files left beside configs the upgrade could not replace"

	case Void:
		h.DBNote = `  /var/db/xbps                                  installed packages

xbps-query is read-only and works. uname is available.`
		h.InspectTools = []string{"Bash(xbps-query:*)"}
		h.ManagerBins = []string{"xbps-install", "xbps-remove", "xbps-pkgdb"}
		h.ConfigConvention = ".new-<version> files left beside configs the upgrade could not replace"

	case Gentoo:
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

	// Cross-distro managers are denied wherever they exist, not per family.
	for _, c := range []string{"flatpak", "snap", "brew", "nix", "pipx"} {
		if hasBin(c) {
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
