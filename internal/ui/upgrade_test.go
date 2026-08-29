package ui

import (
	"os/exec"
	"strings"
	"testing"
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
