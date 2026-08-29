package render

import (
	"strings"
	"testing"
)

func TestFindVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Verdict
		ok   bool
	}{
		{"heading form", "## VERDICT: INSTALL NOW\nReachable by opening a file.", InstallNow, true},
		{"bold form", "**VERDICT — ROUTINE.** Hosting move plus rebuild.", Routine, true},
		{"lowercase", "verdict: investigate", Investigate, true},
		{"trailing prose", "## VERDICT: WAIT\nA regression makes it worth delaying.", Wait, true},
		{
			// INSTALL SOON must not be matched as INSTALL NOW, and must not be
			// truncated to a bare INSTALL.
			"soon not now",
			"## VERDICT: INSTALL SOON\nA real fix with no urgent exposure.",
			InstallSoon, true,
		},
		{
			// The brief hands the model a glossary naming every verdict, and
			// the analysis may quote it. Extraction must return the answer,
			// not whichever verdict word the glossary happens to list first.
			"glossary before answer",
			"The verdict line means: INSTALL NOW, reachable; ROUTINE, no security\n" +
				"content; WAIT, a known regression.\n\n## VERDICT: INSTALL SOON\nBecause.",
			InstallSoon, true,
		},
		{"absent", "No conclusion was reached.", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := FindVerdict(c.in)
			if ok != c.ok || got != c.want {
				t.Fatalf("FindVerdict() = %q,%v; want %q,%v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestUrgency(t *testing.T) {
	for v, want := range map[Verdict]int{
		InstallNow: 2, Investigate: 2,
		InstallSoon: 1, Wait: 1,
		Routine: 0,
	} {
		if got := Urgency(v); got != want {
			t.Errorf("Urgency(%q) = %d; want %d", v, got, want)
		}
	}
}

func TestMarkdownRenders(t *testing.T) {
	const md = "## VERDICT: ROUTINE\n\nA **bold** claim and `code`.\n\n- one\n- two\n"
	out := Markdown(md, 60)

	if out == "" {
		t.Fatal("Markdown() returned empty")
	}
	// The point of rendering is that syntax stops being visible.
	for _, syntax := range []string{"##", "**", "`"} {
		if strings.Contains(out, syntax) {
			t.Errorf("rendered output still contains raw %q:\n%s", syntax, out)
		}
	}
	if !strings.Contains(out, "VERDICT") || !strings.Contains(out, "bold") {
		t.Errorf("rendered output lost its content:\n%s", out)
	}
}

func TestMarkdownEmpty(t *testing.T) {
	if got := Markdown("   \n ", 80); got != "" {
		t.Errorf("Markdown(blank) = %q; want empty", got)
	}
}
