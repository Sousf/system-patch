// Package cache provides the two on-disk stores and the shared HTTP helper.
//
// Two stores, in two places, because they answer to different lifetimes:
//
//	cache/  XDG_CACHE_HOME  release notes keyed by pkg@version. Disposable;
//	                        deleting it costs one refetch and nothing else.
//	state/  XDG_STATE_HOME  the AUR maintainer baseline. Must survive reboots
//	                        and cache clears, because a maintainer *change* is
//	                        a diff against history. Put it in the cache and the
//	                        supply-chain check silently stops working the first
//	                        time someone tidies up.
package cache

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const userAgent = "patchlens/0.1"

var client = &http.Client{Timeout: 25 * time.Second}

func xdg(env, fallback string) string {
	base := os.Getenv(env)
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, fallback)
	}
	p := filepath.Join(base, "patchlens")
	_ = os.MkdirAll(p, 0o700)
	return p
}

// Dir is the disposable cache directory.
func Dir() string { return xdg("XDG_CACHE_HOME", ".cache") }

// StateDir is the durable state directory.
func StateDir() string { return xdg("XDG_STATE_HOME", filepath.Join(".local", "state")) }

func safe(key string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '.', r == '_', r == '@':
			return r
		}
		return '_'
	}, key)
}

// Get decodes a cached value into v. Returns false if absent, stale or corrupt.
func Get(key string, maxAge time.Duration, v any) bool {
	p := filepath.Join(Dir(), safe(key)+".json")
	fi, err := os.Stat(p)
	if err != nil || time.Since(fi.ModTime()) > maxAge {
		return false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// Put stores a value under key.
func Put(key string, v any) {
	_ = WriteJSON(filepath.Join(Dir(), safe(key)+".json"), v)
}

// WriteJSON writes atomically: a temp file named with the PID, then rename.
//
// A shared "<dest>.new" lets two concurrent writers rename each other's
// half-written bytes into place. The PID suffix makes each writer's temp file
// its own, and rename(2) within a directory is atomic.
func WriteJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadJSON decodes path into v, reporting whether it existed and parsed.
func ReadJSON(path string, v any) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

var (
	tokenOnce sync.Once
	token     string
)

// GitHubToken reuses the gh CLI's token when one is available.
//
// Unauthenticated api.github.com allows 60 requests/hour, which a machine with
// a dozen GitHub-hosted packages can exhaust in two runs. Authenticated raises
// it to 5000. A failure here is never fatal — the adapters just run
// unauthenticated.
func GitHubToken() string {
	tokenOnce.Do(func() {
		if t := os.Getenv("GITHUB_TOKEN"); t != "" {
			token = t
			return
		}
		if _, err := exec.LookPath("gh"); err != nil {
			return
		}
		out, err := exec.Command("gh", "auth", "token").Output()
		if err == nil {
			token = strings.TrimSpace(string(out))
		}
	})
	return token
}

// FetchText GETs a URL and returns the body.
//
// Separate from FetchJSON because the Arch news feed is RSS: same transport
// and limits, different parser.
func FetchText(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return string(b), err
}

// FetchJSON GETs a URL and decodes it into v.
//
// The error is returned rather than swallowed: a network failure must leave
// the caller's previous data alone, because "unreachable" and "nothing found"
// are different answers to "should I patch this".
func FetchJSON(url string, auth bool, v any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if auth {
		if t := GitHubToken(); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Capped so a malformed or hostile endpoint cannot exhaust memory. The
	// largest real response here is the Chrome feed at roughly 1 MB.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
