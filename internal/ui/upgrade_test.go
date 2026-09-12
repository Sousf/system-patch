package ui

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/Sousf/system-patch/internal/agent"
	"github.com/Sousf/system-patch/internal/model"
	"github.com/Sousf/system-patch/internal/sources"
)

func TestShellJoinQuotesDangerousArgs(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"plain", []string{"paru", "-Syu"}, "paru -Syu"},
		{"path", []string{"/home/p/.oh-my-zsh/tools/upgrade.sh"},
			"/home/p/.oh-my-zsh/tools/upgrade.sh"},
		{
			// The real reason this function exists: the Neovim command is a Lua
			// snippet with spaces, braces and parentheses. Unquoted it becomes
			// several broken arguments and the upgrade silently does nothing.
			"lua snippet",
			[]string{"nvim", "--headless", "+lua vim.pack.update(nil, {force=true})", "+qa"},
			`nvim --headless '+lua vim.pack.update(nil, {force=true})' +qa`,
		},
		{"embedded quote", []string{"echo", "it's"}, `echo 'it'\''s'`},
		{"empty arg", []string{"x", ""}, "x ''"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shellJoin(c.argv); got != c.want {
				t.Fatalf("shellJoin(%q)\n got %s\nwant %s", c.argv, got, c.want)
			}
		})
	}
}

// TestShellJoinRoundTrips proves the quoting survives a real shell: sh must
// hand back exactly the arguments that went in. A unit test on the string
// alone would not catch a quoting rule that looks right and parses wrong.
func TestShellJoinRoundTrips(t *testing.T) {
	argv := []string{"+lua vim.pack.update(nil, {force=true})", "it's", "a*b", "$HOME"}
	var parts []string
	for _, a := range argv {
		parts = append(parts, shellJoin([]string{"printf", "%s\\n", a}))
	}
	out, err := exec.Command("sh", "-c", strings.Join(parts, "; ")).Output()
	if err != nil {
		t.Fatalf("sh failed: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(got) != len(argv) {
		t.Fatalf("got %d lines, want %d: %q", len(got), len(argv), got)
	}
	for i := range argv {
		if got[i] != argv[i] {
			t.Errorf("arg %d: got %q, want %q", i, got[i], argv[i])
		}
	}
}

// TestInstallPlanMatchesSelection is the contract the install key keeps:
// what you selected is what gets installed, except where no safe
// single-package path exists — and then the plan says so.
func TestInstallPlanMatchesSelection(t *testing.T) {
	m := New()
	m.updates = []model.Update{
		agent.SystemUpdate,
		{Name: "google-chrome", Origin: model.AUR},
		{Name: "org.freedesktop.Platform.GL.default/25.08", Origin: model.Flatpak},
		{Name: "openssl", Origin: model.Repo},
	}

	sel := func(i int) installPlan { m.cursor = i; return m.installPlan() }

	if p := sel(1); p.full || strings.Join(p.argv, " ") != "paru -S google-chrome" {
		t.Errorf("AUR selection: got %+v", p)
	}
	if p := sel(2); p.full ||
		strings.Join(p.argv, " ") != "flatpak update org.freedesktop.Platform.GL.default" {
		t.Errorf("flatpak selection: got %+v", p)
	}
	// A repository package follows the host. Most families upgrade one as a
	// matter of routine; where that is genuinely unsafe the plan stops and
	// says so, because install on one row must never become upgrade
	// everything behind a y.
	p := sel(3)
	if cmd := sources.Host().SingleUpgradeCmd("openssl"); cmd != nil {
		if p.full || p.blocked != "" {
			t.Errorf("repo selection should upgrade just that package here: got %+v", p)
		}
		if strings.Join(p.argv, " ") != strings.Join(cmd, " ") {
			t.Errorf("repo selection: got %q, want %q",
				strings.Join(p.argv, " "), strings.Join(cmd, " "))
		}
	} else {
		if p.full {
			t.Errorf("repo selection widened to the full upgrade: got %+v", p)
		}
		if p.blocked == "" {
			t.Errorf("repo selection must say why it cannot run: got %+v", p)
		}
	}
	if p := sel(0); !p.full || p.why != "" {
		t.Errorf("system row: got %+v", p)
	}
}
