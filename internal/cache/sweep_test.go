package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func age(t *testing.T, path string, by time.Duration) {
	t.Helper()
	old := time.Now().Add(-by)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSweep(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := Dir()

	// The invariant under test: a file older than its class TTL is invisible
	// to every reader, so sweeping it must remove it; anything younger must
	// survive. One case each side of every boundary.
	keep := []string{
		"notes-fresh.json",
		"analysis-fresh.json",
		"updates.json",
	}
	drop := []string{
		"notes-dead.json",
		"analysis-dead.json",
		"arch-news-dead.json",
	}
	for _, f := range append(append([]string{}, keep...), drop...) {
		touch(t, filepath.Join(dir, f))
	}
	age(t, filepath.Join(dir, "notes-fresh.json"), NotesTTL-time.Hour)
	age(t, filepath.Join(dir, "notes-dead.json"), NotesTTL+time.Hour)
	age(t, filepath.Join(dir, "analysis-fresh.json"), AnalysisTTL-time.Hour)
	age(t, filepath.Join(dir, "analysis-dead.json"), AnalysisTTL+time.Hour)
	age(t, filepath.Join(dir, "arch-news-dead.json"), defaultTTL+time.Hour)

	// Scratch directories: a fresh one may belong to a live run and must
	// survive; a day-old one was orphaned by a kill.
	touch(t, filepath.Join(dir, "work", "run-live", "clone", "f.c"))
	touch(t, filepath.Join(dir, "work", "run-dead", "clone", "f.c"))
	age(t, filepath.Join(dir, "work", "run-dead"), workTTL+time.Hour)

	// The state directory holds the AUR maintainer baseline, whose entire
	// job is surviving cleanups. The sweeper must never look at it.
	statePath := filepath.Join(StateDir(), "maintainers.json")
	touch(t, statePath)
	age(t, statePath, 400*24*time.Hour)

	Sweep()

	for _, f := range keep {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s should have survived: %v", f, err)
		}
	}
	for _, f := range drop {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s should have been swept", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "run-live")); err != nil {
		t.Errorf("fresh work dir should have survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "run-dead")); !os.IsNotExist(err) {
		t.Error("orphaned work dir should have been swept")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("state must never be swept: %v", err)
	}
}
