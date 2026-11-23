package hostbound

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNewPlaceholder(t *testing.T) {
	var previous string
	for range 2 {
		p, err := NewPlaceholder("MY_API_KEY")
		if err != nil {
			t.Fatal(err)
		}
		suffix, ok := strings.CutPrefix(p, "hostbound-MY_API_KEY-")
		if _, err := hex.DecodeString(suffix); !ok || err != nil || len(suffix) != 32 || p == previous {
			t.Fatalf("unexpected placeholder %q", p)
		}
		previous = p
	}
}

func TestClientEnv(t *testing.T) {
	api := Binding{ID: "MY_API_KEY", Hosts: []string{"api.example.com"}, Placeholder: "api-placeholder"}
	git := Binding{ID: "GITHUB_PAT", Hosts: []string{"github.com", "api.github.com"}, Placeholder: "git-placeholder", Injects: []Injection{bearerInjection, {BasicUser: "x-access-token"}, {BasicUser: "other"}}}
	env := []string{
		"NO_PROXY=old.example", "NO_PROXY=internal.example, localhost", "no_proxy=svc.local",
		"HTTPS_PROXY=http://user-proxy:3128",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.editor", "GIT_CONFIG_VALUE_0=true",
		"MY_API_KEY=old-api-value", "MY_API_KEY=another-api-value", "GITHUB_PAT=old-git-value", "OTHER=a=b",
	}
	original := slices.Clone(env)
	got := ClientEnv(env, "http://127.0.0.1:41234", "/run/x/proxy-ca.pem", "/run/x/ca-bundle.pem", []Binding{api, git})
	if !slices.Equal(env, original) {
		t.Fatal("ClientEnv modified the supplied environment")
	}
	helper := `!f() { printf '%s\n' 'username=x-access-token' 'password=git-placeholder'; }; f`
	want := []string{
		"MY_API_KEY=api-placeholder", "GITHUB_PAT=git-placeholder", "OTHER=a=b",
		"HTTPS_PROXY=http://127.0.0.1:41234", "https_proxy=http://127.0.0.1:41234",
		"NO_PROXY=internal.example,localhost,svc.local,127.0.0.1,::1",
		"no_proxy=internal.example,localhost,svc.local,127.0.0.1,::1",
		"NODE_USE_ENV_PROXY=1", "NODE_EXTRA_CA_CERTS=/run/x/proxy-ca.pem",
		"SSL_CERT_FILE=/run/x/ca-bundle.pem", "REQUESTS_CA_BUNDLE=/run/x/ca-bundle.pem",
		"CURL_CA_BUNDLE=/run/x/ca-bundle.pem", "GIT_SSL_CAINFO=/run/x/ca-bundle.pem",
		"GIT_CONFIG_COUNT=5", "GIT_CONFIG_KEY_0=core.editor", "GIT_CONFIG_VALUE_0=true",
		"GIT_CONFIG_KEY_1=credential.https://github.com.helper", "GIT_CONFIG_VALUE_1=",
		"GIT_CONFIG_KEY_2=credential.https://github.com.helper", "GIT_CONFIG_VALUE_2=" + helper,
		"GIT_CONFIG_KEY_3=credential.https://api.github.com.helper", "GIT_CONFIG_VALUE_3=",
		"GIT_CONFIG_KEY_4=credential.https://api.github.com.helper", "GIT_CONFIG_VALUE_4=" + helper,
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("client environment = %q, want %q", got, want)
	}
	if got := ClientEnv(env, "", "", "", nil); !slices.Equal(got, original) {
		t.Fatal("empty bindings changed the environment")
	}
}

func TestWriteCAFiles(t *testing.T) {
	p, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	dir := t.TempDir()
	base := bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newTestCA(t).cert.Raw}))
	ca, bundle, err := p.WriteCAFiles(dir, base)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{ca: p.CACertPEM(), bundle: slices.Concat(base, []byte("\n"), p.CACertPEM())} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("unexpected contents in %s (read error %v)", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode of %s = %v", path, info.Mode())
		}
	}
	if err := os.Remove(ca); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.WriteCAFiles(dir, nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("writing over existing bundle: %v", err)
	}
	if _, err := os.Stat(ca); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CA file left by failed write: %v", err)
	}
}

func TestChildProcesses(t *testing.T) {
	const ref = "0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n"
	ca := newTestCA(t)
	api := headerBinding(staticToken(nil))
	api.ID = "MY_API_KEY"
	git := basicBinding(staticToken(nil))
	git.Placeholder = "my git 'placeholder'"
	git.ID = "GIT_TOKEN"
	echo := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Authorization"))
	})
	repo := startUpstream(t, ca, basicHost, func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); !ok || user != basicUser || password != realToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/repo/info/refs":
			io.WriteString(w, ref)
		case "/repo/HEAD":
			io.WriteString(w, "ref: refs/heads/main\n")
		default:
			http.NotFound(w, r)
		}
	})
	bindings := []Binding{api, git}
	h := startProxy(t, Config{Bindings: bindings, ScanResponses: true}, ca.pool, map[string]string{
		boundHost + ":443": echo.srv.Listener.Addr().String(), basicHost + ":443": repo.srv.Listener.Addr().String(),
	})
	caFile, bundle, err := h.proxy.WriteCAFiles(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	env := ClientEnv([]string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_SMART_HTTP=0", "MY_API_KEY=" + realToken, "GIT_TOKEN=" + realToken},
		"http://"+h.addr, caFile, bundle, bindings)
	run := func(t *testing.T, input string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env, cmd.Dir = env, home
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if bytes.Contains(out, []byte(realToken)) {
			t.Fatal("child output contained the real credential")
		}
		if err != nil {
			t.Fatalf("%s: %v: %s", filepath.Base(args[0]), err, out)
		}
		return string(out)
	}
	t.Run("curl", func(t *testing.T) {
		curl, err := exec.LookPath("curl")
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("curl is not installed")
		}
		if err != nil {
			t.Fatal(err)
		}
		got := run(t, "", "sh", "-c", `exec "$1" -qfsS -H "Authorization: Bearer $MY_API_KEY" "$2"`, "sh", curl, "https://"+boundHost+"/echo")
		if got != "Bearer "+api.Placeholder {
			t.Fatalf("curl received %q", got)
		}
		if seen := echo.seen(); len(seen) != 1 || seen[0].header.Get("Authorization") != "Bearer "+realToken {
			t.Fatal("upstream did not receive the credential")
		}
	})
	t.Run("git", func(t *testing.T) {
		path, err := exec.LookPath("git")
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("git is not installed")
		}
		if err != nil {
			t.Fatal(err)
		}
		got := run(t, fmt.Sprintf("protocol=https\nhost=%s\n\n", basicHost), path, "credential", "fill")
		lines := strings.Split(got, "\n")
		if !slices.Contains(lines, "username="+basicUser) || !slices.Contains(lines, "password="+git.Placeholder) {
			t.Fatalf("git credential fill returned %q", got)
		}
		if got := run(t, "", path, "ls-remote", "https://"+basicHost+"/repo", "refs/heads/main"); got != ref {
			t.Fatalf("git ls-remote returned %q", got)
		}
	})
}
