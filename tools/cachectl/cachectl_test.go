package main

// ─── Tests ─────────────────────────────────────────────────────────

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// ─── fakeRunner ────────────────────────────────────────────────────

type fakeResp struct {
	out string
	err error
}

// fakeRunner implements Runner with a scripted response queue.
type fakeRunner struct {
	responses []fakeResp
	calls     []string
	next      int
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.next >= len(f.responses) {
		return "", fmt.Errorf("fakeRunner: unexpected call #%d", f.next)
	}
	r := f.responses[f.next]
	f.next++
	return r.out, r.err
}

func (f *fakeRunner) lastCall() string {
	if len(f.calls) == 0 {
		return ""
	}
	return f.calls[len(f.calls)-1]
}

// ok returns a success response (empty stdout, no error).
func okResp() fakeResp { return fakeResp{} }

// outResp returns a response with the given stdout.
func outResp(s string) fakeResp { return fakeResp{out: s} }

// errResp returns a response with an error (test -e / test -f not found).
func errResp() fakeResp { return fakeResp{err: fmt.Errorf("exit status 1")} }

// failResp returns a response with a specific error message.
func failResp(msg string) fakeResp { return fakeResp{err: fmt.Errorf("%s", msg)} }

// newTestEdge creates an edge with a fake runner and buffer output.
func newTestEdge(r *fakeRunner, in io.Reader) edge {
	return edge{
		cfg: config{
			sshHost:   "router",
			container: "caddy",
			hostRoot:  "/var/lib/caddy/data/cache/nuts",
			ctrRoot:   "/data/cache/nuts",
		},
		r:   r,
		out: new(bytes.Buffer),
		in:  in,
	}
}

// outStr returns the captured output buffer as a string.
func outStr(e edge) string { return e.out.(*bytes.Buffer).String() }

// ─── parseConfiguredDirs ───────────────────────────────────────────

func TestParseConfiguredDirs(t *testing.T) {
	ctr := "/data/cache/nuts"
	tests := []struct {
		name, caddyfile string
		want            []string
	}{
		{
			name:      "tab-indented Dir entries",
			caddyfile: "\tDir /data/cache/nuts/docs\n\tDir /data/cache/nuts/jellyfin",
			want:      []string{"/data/cache/nuts/docs", "/data/cache/nuts/jellyfin"},
		},
		{
			name:      "duplicates deduped and sorted",
			caddyfile: "Dir /data/cache/nuts/zzz\nDir /data/cache/nuts/aaa\nDir /data/cache/nuts/zzz",
			want:      []string{"/data/cache/nuts/aaa", "/data/cache/nuts/zzz"},
		},
		{
			name:      "Dir outside ctrRoot ignored",
			caddyfile: "Dir /data/cache/nuts/docs\nDir /tmp/souin-nuts\nDir /other/path",
			want:      []string{"/data/cache/nuts/docs"},
		},
		{
			name:      "empty Caddyfile",
			caddyfile: "",
			want:      nil,
		},
		{
			name:      "no cache blocks",
			caddyfile: "somedomain.erfi.io {\n\treverse_proxy localhost:8080\n}\n",
			want:      nil,
		},
		{
			name:      "single entry",
			caddyfile: "Dir /data/cache/nuts/navidrome",
			want:      []string{"/data/cache/nuts/navidrome"},
		},
		{
			name:      "realistic multi-site fixture",
			caddyfile: "docs.erfi.io {\n\tcache {\n\t\tnuts {\n\t\t\tconfiguration {\n\t\t\t\tDir /data/cache/nuts/docs\n\t\t\t\tEntryIdxMode HintKeyAndRAMIdxMode\n\t\t\t}\n\t\t}\n\t}\n}\njellyfin.erfi.io {\n\tcache {\n\t\tnuts {\n\t\t\tconfiguration {\n\t\t\t\tDir /data/cache/nuts/jellyfin\n\t\t\t}\n\t\t}\n\t}\n}",
			want:      []string{"/data/cache/nuts/docs", "/data/cache/nuts/jellyfin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseConfiguredDirs(tt.caddyfile, ctr)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// ─── parseCacheStatus ──────────────────────────────────────────────

func TestParseCacheStatus(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   cacheStatus
	}{
		{
			name:   "fwd uri-miss stored detail NUTS",
			header: "Souin; fwd=uri-miss; stored; key=GET-abc; detail=NUTS",
			want:   cacheStatus{Raw: "Souin; fwd=uri-miss; stored; key=GET-abc; detail=NUTS", Fwd: "uri-miss", Stored: true, Detail: "NUTS"},
		},
		{
			name:   "hit stored detail NUTS",
			header: "Souin; hit; stored; detail=NUTS",
			want:   cacheStatus{Raw: "Souin; hit; stored; detail=NUTS", Hit: true, Stored: true, Detail: "NUTS"},
		},
		{
			name:   "hit stored detail DEFAULT",
			header: "Souin; hit; stored; detail=DEFAULT",
			want:   cacheStatus{Raw: "Souin; hit; stored; detail=DEFAULT", Hit: true, Stored: true, Detail: "DEFAULT"},
		},
		{
			name:   "missing fields",
			header: "Souin",
			want:   cacheStatus{Raw: "Souin"},
		},
		{
			name:   "empty header",
			header: "",
			want:   cacheStatus{},
		},
		{
			name:   "fwd request",
			header: "Souin; fwd=request; stored",
			want:   cacheStatus{Raw: "Souin; fwd=request; stored", Fwd: "request", Stored: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCacheStatus(tt.header)
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// ─── shellQuote ────────────────────────────────────────────────────

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"simple", "hello", "'hello'"},
		{"embedded single quote", "it's", "'it'\\''s'"},
		{"empty", "", "''"},
		{"multiple quotes", "a'b'c", "'a'\\''b'\\''c'"},
		{"spaces", "rm -rf /data/cache/nuts", "'rm -rf /data/cache/nuts'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ─── parsePurgeArgs ────────────────────────────────────────────────

func TestParsePurgeArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantSite string
		wantYes  bool
	}{
		{"site only", []string{"mysite"}, "mysite", false},
		{"site with -y", []string{"mysite", "-y"}, "mysite", true},
		{"-y before site", []string{"-y", "mysite"}, "mysite", true},
		{"all with -y", []string{"all", "-y"}, "all", true},
		{"all without -y", []string{"all"}, "all", false},
		{"empty args", []string{}, "", false},
		{"just -y", []string{"-y"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSite, gotYes := parsePurgeArgs(tt.args)
			if gotSite != tt.wantSite || gotYes != tt.wantYes {
				t.Errorf("parsePurgeArgs(%v) = (%q, %v), want (%q, %v)",
					tt.args, gotSite, gotYes, tt.wantSite, tt.wantYes)
			}
		})
	}
}

// ─── cmdVerify ─────────────────────────────────────────────────────

const twoSiteCaddyfile = `docs.erfi.io {
	cache {
		nuts {
			configuration {
				Dir /data/cache/nuts/docs
				EntryIdxMode HintKeyAndRAMIdxMode
			}
		}
	}
}
jellyfin.erfi.io {
	cache {
		nuts {
			configuration {
				Dir /data/cache/nuts/jellyfin
			}
		}
	}
}`

const oneSiteCaddyfile = `docs.erfi.io {
	cache {
		nuts {
			configuration {
				Dir /data/cache/nuts/docs
			}
		}
	}
}`

const noSiteCaddyfile = `erfianugrah.com {
	reverse_proxy localhost:4321
}`

func TestCmdVerify_AllPass(t *testing.T) {
	// Sequence:
	//   [0] fallbackWarnings → "0\n"
	//   [1] dockerExec cat Caddyfile → fixture
	//   [2] dockerExec test -f /data/cache/nuts/docs/0.dat → OK
	//   [3] dockerExec test -f /data/cache/nuts/jellyfin/0.dat → OK
	//   [4] dockerExec test -e /tmp/souin-nuts/0.dat → error (not found → pass)
	fr := &fakeRunner{responses: []fakeResp{
		outResp("0\n"),            // fallback count
		outResp(twoSiteCaddyfile), // Caddyfile
		okResp(),                  // docs 0.dat exists
		okResp(),                  // jellyfin 0.dat exists
		errResp(),                 // /tmp/souin-nuts/0.dat absent
	}}
	e := newTestEdge(fr, nil)
	code := cmdVerify(e)
	if code != 0 {
		t.Errorf("cmdVerify returned %d, want 0", code)
	}
	if !strings.Contains(outStr(e), "VERIFY OK") {
		t.Errorf("output missing VERIFY OK:\n%s", outStr(e))
	}
}

func TestCmdVerify_FallbackWarning(t *testing.T) {
	fr := &fakeRunner{responses: []fakeResp{
		outResp("3\n"),            // fallback count = 3
		outResp(twoSiteCaddyfile), // Caddyfile
		okResp(),                  // docs
		okResp(),                  // jellyfin
		errResp(),                 // tmpfs absent
	}}
	e := newTestEdge(fr, nil)
	code := cmdVerify(e)
	if code != 1 {
		t.Errorf("cmdVerify returned %d, want 1", code)
	}
	if !strings.Contains(outStr(e), "VERIFY FAILED") {
		t.Errorf("output missing VERIFY FAILED:\n%s", outStr(e))
	}
	if !strings.Contains(outStr(e), "FAIL") {
		t.Errorf("output missing FAIL for fallback:\n%s", outStr(e))
	}
}

func TestCmdVerify_MissingDBFile(t *testing.T) {
	fr := &fakeRunner{responses: []fakeResp{
		outResp("0\n"),            // fallback OK
		outResp(twoSiteCaddyfile), // Caddyfile
		okResp(),                  // docs OK
		errResp(),                 // jellyfin 0.dat missing!
		errResp(),                 // tmpfs absent
	}}
	e := newTestEdge(fr, nil)
	code := cmdVerify(e)
	if code != 1 {
		t.Errorf("cmdVerify returned %d, want 1", code)
	}
	if !strings.Contains(outStr(e), "VERIFY FAILED") {
		t.Errorf("output missing VERIFY FAILED:\n%s", outStr(e))
	}
}

func TestCmdVerify_TmpfsTrap(t *testing.T) {
	fr := &fakeRunner{responses: []fakeResp{
		outResp("0\n"),            // fallback OK
		outResp(oneSiteCaddyfile), // Caddyfile (one dir)
		okResp(),                  // docs OK
		okResp(),                  // /tmp/souin-nuts/0.dat EXISTS (trap!)
	}}
	e := newTestEdge(fr, nil)
	code := cmdVerify(e)
	if code != 1 {
		t.Errorf("cmdVerify returned %d, want 1", code)
	}
	if !strings.Contains(outStr(e), "VERIFY FAILED") {
		t.Errorf("output missing VERIFY FAILED:\n%s", outStr(e))
	}
}

func TestCmdVerify_NoConfiguredDirs(t *testing.T) {
	fr := &fakeRunner{responses: []fakeResp{
		outResp("0\n"),           // fallback OK
		outResp(noSiteCaddyfile), // Caddyfile with no Dir entries
		errResp(),                // tmpfs absent
	}}
	e := newTestEdge(fr, nil)
	code := cmdVerify(e)
	if code != 1 {
		t.Errorf("cmdVerify returned %d, want 1", code)
	}
}

// ─── cmdPurge ──────────────────────────────────────────────────────

func TestCmdPurge_InvalidSite(t *testing.T) {
	e := newTestEdge(&fakeRunner{}, nil)
	err := cmdPurge(e, "bad/site!", false)
	if err == nil {
		t.Fatal("expected error for invalid site name")
	}
	if !strings.Contains(err.Error(), "invalid site name") {
		t.Errorf("error = %v, want 'invalid site name'", err)
	}
}

func TestCmdPurge_InvalidSiteSpecialChars(t *testing.T) {
	e := newTestEdge(&fakeRunner{}, nil)
	err := cmdPurge(e, "foo bar", false)
	if err == nil {
		t.Fatal("expected error for site with space")
	}
}

func TestCmdPurge_SiteYes(t *testing.T) {
	// Sequence:
	//   [0] docker exec rm -rf /data/cache/nuts/mysite
	//   [1] docker restart caddy
	fr := &fakeRunner{responses: []fakeResp{
		okResp(), // rm -rf succeeds
		okResp(), // docker restart succeeds
	}}
	e := newTestEdge(fr, nil)
	err := cmdPurge(e, "mysite", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(fr.calls), fr.calls)
	}
	// Call [0] must be the rm -rf via docker exec
	if !strings.Contains(fr.calls[0], "rm -rf /data/cache/nuts/mysite") {
		t.Errorf("call[0] missing rm -rf: %s", fr.calls[0])
	}
	// Call [1] must be docker restart
	if !strings.Contains(fr.calls[1], "docker restart caddy") {
		t.Errorf("call[1] missing docker restart: %s", fr.calls[1])
	}
	// Output confirms purge + restart
	o := outStr(e)
	if !strings.Contains(o, "purged /data/cache/nuts/mysite + restarted caddy") {
		t.Errorf("output missing confirmation:\n%s", o)
	}
	if !strings.Contains(o, "nuts re-creates dirs at open") {
		t.Errorf("output missing nuts note:\n%s", o)
	}
}

func TestCmdPurge_AllYes(t *testing.T) {
	// Sequence:
	//   [0] docker exec rm -rf /data/cache/nuts; mkdir -p /data/cache/nuts
	//   [1] docker restart caddy
	fr := &fakeRunner{responses: []fakeResp{
		okResp(), // rm -rf + mkdir -p succeeds
		okResp(), // docker restart succeeds
	}}
	e := newTestEdge(fr, nil)
	err := cmdPurge(e, "all", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(fr.calls), fr.calls)
	}
	// Call [0] must contain both rm -rf and mkdir -p
	if !strings.Contains(fr.calls[0], "rm -rf /data/cache/nuts") {
		t.Errorf("call[0] missing rm -rf: %s", fr.calls[0])
	}
	if !strings.Contains(fr.calls[0], "mkdir -p /data/cache/nuts") {
		t.Errorf("call[0] missing mkdir -p: %s", fr.calls[0])
	}
	// rm -rf must come before mkdir -p in the same command
	rmIdx := strings.Index(fr.calls[0], "rm -rf")
	mkIdx := strings.Index(fr.calls[0], "mkdir -p")
	if rmIdx > mkIdx {
		t.Errorf("rm -rf must precede mkdir -p in call[0]: %s", fr.calls[0])
	}
	// Call [1] must be docker restart
	if !strings.Contains(fr.calls[1], "docker restart caddy") {
		t.Errorf("call[1] missing docker restart: %s", fr.calls[1])
	}
	o := outStr(e)
	if !strings.Contains(o, "purged /data/cache/nuts + restarted caddy") {
		t.Errorf("output missing confirmation:\n%s", o)
	}
}

func TestCmdPurge_ConfirmYes(t *testing.T) {
	// User types "y" → proceed.
	fr := &fakeRunner{responses: []fakeResp{
		okResp(), // rm -rf
		okResp(), // docker restart
	}}
	e := newTestEdge(fr, strings.NewReader("y\n"))
	err := cmdPurge(e, "mysite", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected 2 calls after confirm, got %d: %v", len(fr.calls), fr.calls)
	}
}

func TestCmdPurge_ConfirmNo(t *testing.T) {
	// User types "n" → abort.
	fr := &fakeRunner{}
	e := newTestEdge(fr, strings.NewReader("n\n"))
	err := cmdPurge(e, "mysite", false)
	if err == nil {
		t.Fatal("expected aborted error")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error = %v, want 'aborted'", err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("expected 0 calls after abort, got %d: %v", len(fr.calls), fr.calls)
	}
}

func TestCmdPurge_ConfirmEmpty(t *testing.T) {
	// User just presses enter → abort.
	fr := &fakeRunner{}
	e := newTestEdge(fr, strings.NewReader("\n"))
	err := cmdPurge(e, "mysite", false)
	if err == nil {
		t.Fatal("expected aborted error on empty input")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error = %v, want 'aborted'", err)
	}
}

func TestCmdPurge_DockerExecFails(t *testing.T) {
	fr := &fakeRunner{responses: []fakeResp{
		failResp("rm: cannot remove"), // rm -rf fails
	}}
	e := newTestEdge(fr, nil)
	err := cmdPurge(e, "mysite", true)
	if err == nil {
		t.Fatal("expected error from failed docker exec")
	}
	if !strings.Contains(err.Error(), "purge mysite") {
		t.Errorf("error should wrap with 'purge mysite': %v", err)
	}
}

func TestCmdPurge_DockerRestartFails(t *testing.T) {
	fr := &fakeRunner{responses: []fakeResp{
		okResp(),                      // rm -rf succeeds
		failResp("docker: not found"), // docker restart fails
	}}
	e := newTestEdge(fr, nil)
	err := cmdPurge(e, "mysite", true)
	if err == nil {
		t.Fatal("expected error from failed restart")
	}
	if !strings.Contains(err.Error(), "restart caddy") {
		t.Errorf("error should wrap with 'restart caddy': %v", err)
	}
}
