package hostbound

import (
	"regexp"
	"strings"
	"testing"
)

var authoritySeeds = []string{
	"api.bound.test",
	"api.bound.test:443",
	"API.BOUND.TEST",
	"api.bound.test.",
	"api.bound.test.:443",
	"api.bound.test..",
	"api.bound.test:8443",
	"api.bound.test:0443",
	"api.bound.test:",
	"api.bound.test:443:443",
	"api.bound.test.evil",
	"evil.api.bound.test",
	"api.bound.test@evil.test",
	"evil.test#api.bound.test",
	"api.bound.test%00",
	"api.bound.test ",
	" api.bound.test",
	"[api.bound.test]:443",
	"[::1]:443",
	"[::ffff:127.0.0.1]",
	"[fe80::1%25eth0]:443",
	"::1",
	"api.bound.tesKt",
	"api.bound.test。",
	"",
	":443",
	"127.0.0.1:443",
}

func TestSameAuthority(t *testing.T) {
	accepted := map[string]bool{
		"api.bound.test": true, "api.bound.test:443": true, "API.BOUND.TEST": true,
		"api.bound.test.": true, "api.bound.test.:443": true,
	}
	for _, a := range authoritySeeds {
		if got := sameAuthority(boundHost, a); got != accepted[a] {
			t.Errorf("sameAuthority(%q) = %v, want %v", a, got, accepted[a])
		}
	}
}

func TestParseAuthority(t *testing.T) {
	for _, tc := range []struct {
		in, host, port string
		ok             bool
	}{
		{"[2001:DB8::1]:443", "2001:db8::1", "443", true},
		{"[::ffff:127.0.0.1]:8080", "::ffff:127.0.0.1", "8080", true},
		{"[fe80::1%25eth0]:443", "", "", false},
		{"[127.0.0.1]:443", "", "", false},
		{"Example.COM.:80", "example.com", "80", true},
		{"example.com:0", "", "", false},
		{"example.com:65536", "", "", false},
		{"exa mple.com:443", "", "", false},
		{"[::1]x", "", "", false},
	} {
		host, port, ok := parseAuthority(tc.in)
		if host != tc.host || port != tc.port || ok != tc.ok {
			t.Errorf("parseAuthority(%q) = %q, %q, %v", tc.in, host, port, ok)
		}
	}
}

func FuzzSameAuthority(f *testing.F) {
	for _, s := range authoritySeeds {
		f.Add(s)
	}
	want := regexp.MustCompile(`^` + regexp.QuoteMeta(boundHost) + `\.?(:443)?$`)
	f.Fuzz(func(t *testing.T, a string) {
		lower := strings.Map(func(r rune) rune {
			if 'A' <= r && r <= 'Z' {
				return r + 'a' - 'A'
			}
			return r
		}, a)
		if got := sameAuthority(boundHost, a); got != want.MatchString(lower) {
			t.Fatalf("sameAuthority(%q) = %v", a, got)
		}
		host, port, ok := parseAuthority(a)
		if !ok {
			return
		}
		if again, p2, ok2 := parseAuthority(host); !strings.Contains(host, ":") && (!ok2 || again != host || p2 != "") {
			t.Fatalf("host %q from %q does not parse to itself", host, a)
		}
		if strings.ToLower(host) != host || strings.HasSuffix(host, ".") || (port != "" && port[0] == ':') {
			t.Fatalf("parseAuthority(%q) = %q, %q", a, host, port)
		}
	})
}
