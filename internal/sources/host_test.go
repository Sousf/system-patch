package sources

import "strings"

import "testing"

// noBins stands for a machine where nothing is on PATH, so a case that passes
// only through os-release is not quietly rescued by a binary check.
func noBins(string) bool { return false }

// Real os-release excerpts. Ubuntu and Mint reach the Debian table only through
// ID_LIKE, which is the path that matters: neither declares ID=debian.
func TestFamilyFromOSRelease(t *testing.T) {
	cases := []struct {
		name string
		rel  map[string]string
		want Family
	}{
		{"arch", map[string]string{"ID": "arch", "PRETTY_NAME": "Arch Linux"}, Arch},
		{"ubuntu", map[string]string{
			"ID": "ubuntu", "ID_LIKE": "debian", "PRETTY_NAME": "Ubuntu 24.04.3 LTS",
		}, Debian},
		{"debian", map[string]string{"ID": "debian", "PRETTY_NAME": "Debian GNU/Linux 12"}, Debian},
		{"mint", map[string]string{"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}, Debian},
		{"fedora", map[string]string{"ID": "fedora", "PRETTY_NAME": "Fedora Linux 41"}, Fedora},
		{"rocky", map[string]string{"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, Fedora},
		{"opensuse", map[string]string{"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"}, SUSE},
		{"alpine", map[string]string{"ID": "alpine"}, Alpine},
		{"void", map[string]string{"ID": "void"}, Void},
		{"gentoo", map[string]string{"ID": "gentoo"}, Gentoo},
		{"endeavouros", map[string]string{"ID": "endeavouros", "ID_LIKE": "arch"}, Arch},
		{"unreadable", map[string]string{}, Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hostFrom(c.rel, noBins).Family; got != c.want {
				t.Fatalf("family = %q, want %q", got, c.want)
			}
		})
	}
}

// Without os-release the only signal left is which manager is installed.
func TestFamilyFallsBackToBinaries(t *testing.T) {
	arch := hostFrom(nil, func(c string) bool { return c == "pacman" })
	if arch.Family != Arch {
		t.Errorf("pacman present: family = %q, want arch", arch.Family)
	}
	deb := hostFrom(nil, func(c string) bool { return c == "dpkg" })
	if deb.Family != Debian {
		t.Errorf("dpkg present: family = %q, want debian", deb.Family)
	}
}

// The Ubuntu run that prompted all this failed on three specific things: a
// prompt naming pacman, read-only tools that do not exist there, and a deny
// list that left apt reachable.
func TestDebianHostIsNotDescribedAsArch(t *testing.T) {
	h := hostFrom(map[string]string{
		"ID": "ubuntu", "ID_LIKE": "debian", "PRETTY_NAME": "Ubuntu 24.04.3 LTS",
	}, noBins)

	if strings.Contains(h.DBNote, "pacman") {
		t.Errorf("database note names pacman on Ubuntu:\n%s", h.DBNote)
	}
	if !strings.Contains(h.DBNote, "dpkg") {
		t.Errorf("database note never mentions dpkg on Ubuntu:\n%s", h.DBNote)
	}
	if h.ArchNews {
		t.Error("Arch news feed marked applicable on Ubuntu")
	}
	if h.Describe() != "Ubuntu 24.04.3 LTS" {
		t.Errorf("Describe() = %q, want the pretty name", h.Describe())
	}
	for _, tool := range h.InspectTools {
		if strings.Contains(tool, "pactree") || strings.Contains(tool, "expac") {
			t.Errorf("Arch-only inspection tool granted on Ubuntu: %s", tool)
		}
	}
}

// The deny list is the guarantee that an analysis cannot install what it is
// judging. It held on Arch alone until the manager set became per-host.
func TestPackageManagersAreDeniedPerFamily(t *testing.T) {
	cases := []struct {
		rel  map[string]string
		bins []string
	}{
		{map[string]string{"ID": "ubuntu", "ID_LIKE": "debian"}, []string{"apt", "apt-get", "dpkg"}},
		{map[string]string{"ID": "fedora"}, []string{"dnf", "rpm"}},
		{map[string]string{"ID": "opensuse-leap", "ID_LIKE": "suse"}, []string{"zypper"}},
		{map[string]string{"ID": "arch"}, []string{"pacman", "paru", "makepkg"}},
		{map[string]string{"ID": "alpine"}, []string{"apk"}},
	}
	for _, c := range cases {
		h := hostFrom(c.rel, noBins)
		denied := strings.Join(h.DeniedTools(), " ")
		for _, bin := range c.bins {
			// Both spellings, since which one the CLI honours is not assumed.
			for _, want := range []string{"Bash(" + bin + ":*)", "Bash(" + bin + " *)"} {
				if !strings.Contains(denied, want) {
					t.Errorf("%s: %q missing from deny list", c.rel["ID"], want)
				}
			}
		}
	}
}

// Cross-distro managers are denied wherever they are installed, independent of
// the family table.
func TestCrossDistroManagersDeniedWhenPresent(t *testing.T) {
	h := hostFrom(map[string]string{"ID": "fedora"},
		func(c string) bool { return c == "flatpak" || c == "snap" })
	denied := strings.Join(h.DeniedTools(), " ")
	for _, want := range []string{"Bash(flatpak:*)", "Bash(snap:*)"} {
		if !strings.Contains(denied, want) {
			t.Errorf("%q missing from deny list", want)
		}
	}
	if strings.Contains(denied, "Bash(brew:*)") {
		t.Error("brew denied on a machine that does not have it")
	}
}

// An unknown distribution must say so rather than describe a database it has
// not got.
func TestUnknownHostAdmitsIt(t *testing.T) {
	h := hostFrom(map[string]string{"ID": "someos"}, noBins)
	if h.Family != Unknown {
		t.Fatalf("family = %q, want unknown", h.Family)
	}
	if !strings.Contains(h.DBNote, "not known") {
		t.Errorf("database note does not admit ignorance:\n%s", h.DBNote)
	}
	for _, bad := range []string{"/var/lib/pacman", "/var/lib/dpkg", "/var/lib/rpm"} {
		if strings.Contains(h.DBNote, bad) {
			t.Errorf("database note invents the path %s", bad)
		}
	}
}

// The deny list must describe the machine running the agent, not the system the
// brief describes. SYSTEM_PATCH_DISTRO selects a family without moving the
// host, and an Unknown family declares no managers at all, so a family-only
// list left the real package manager reachable in both cases.
func TestDenyListCoversTheRealMachine(t *testing.T) {
	here := func(c string) bool { return c == "pacman" || c == "paru" || c == "makepkg" }

	// Previewing an Ubuntu brief from an Arch box.
	h := hostFrom(map[string]string{"ID": "ubuntu", "ID_LIKE": "debian"}, here)
	denied := strings.Join(h.DeniedTools(), " ")
	for _, bin := range []string{"pacman", "paru", "makepkg"} {
		if !strings.Contains(denied, "Bash("+bin+":*)") {
			t.Errorf("override to ubuntu left %q reachable on a pacman host", bin)
		}
	}
	if !strings.Contains(denied, "Bash(apt:*)") {
		t.Error("override to ubuntu dropped apt from the deny list")
	}

	// A distribution the table does not know still denies what is installed.
	u := hostFrom(map[string]string{"ID": "someos"}, here)
	if u.Family != Unknown {
		t.Fatalf("family = %q, want unknown", u.Family)
	}
	ud := strings.Join(u.DeniedTools(), " ")
	if !strings.Contains(ud, "Bash(pacman:*)") {
		t.Error("unknown family denied nothing while the brief claims the manager is blocked")
	}
}

// A tool cannot be both granted and denied. Doing so recreates the wasted turns
// the database note exists to prevent, since the note names the granted tools.
func TestNoToolIsBothGrantedAndDenied(t *testing.T) {
	for _, id := range []string{"arch", "ubuntu", "fedora", "opensuse-leap", "alpine", "void", "gentoo"} {
		h := hostFrom(map[string]string{"ID": id, "ID_LIKE": derivativeLike(id)}, func(string) bool { return false })
		denied := strings.Join(h.DeniedTools(), " ")
		for _, g := range h.InspectTools {
			if strings.Contains(denied, g) {
				t.Errorf("%s: %s is both granted and denied", id, g)
			}
		}
	}
}

// Every manager binary is denied once. Listing it in the family table and then
// again by presence emitted the same pattern twice.
func TestDenyListHasNoDuplicates(t *testing.T) {
	h := hostFrom(map[string]string{"ID": "ubuntu", "ID_LIKE": "debian"},
		func(c string) bool { return c == "snap" || c == "flatpak" })
	seen := map[string]bool{}
	for _, d := range h.DeniedTools() {
		if seen[d] {
			t.Errorf("%q appears twice in the deny list", d)
		}
		seen[d] = true
	}
}

// The override exists to preview another system, and the systems worth
// previewing are mostly derivatives that reach a family through ID_LIKE.
func TestOverrideResolvesDerivatives(t *testing.T) {
	cases := map[string]Family{
		"linuxmint":           Debian,
		"rocky":               Fedora,
		"endeavouros":         Arch,
		"opensuse-tumbleweed": SUSE,
		"ubuntu":              Debian,
	}
	for id, want := range cases {
		rel := map[string]string{"ID": id}
		if like := derivativeLike(id); like != "" {
			rel["ID_LIKE"] = like
		}
		if got := hostFrom(rel, func(string) bool { return false }).Family; got != want {
			t.Errorf("SYSTEM_PATCH_DISTRO=%s -> %q, want %q", id, got, want)
		}
	}
}
