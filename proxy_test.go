package hostbound

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	boundHost   = "api.bound.test"
	basicHost   = "git.bound.test"
	otherHost   = "other.test"
	placeholder = "proxy-placeholder-0001"
	realToken   = "real-token-7f3a9c41d2"
	basicUser   = "x-access-token"
)

type testCA struct {
	pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "upstream test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{pool: pool, cert: cert, key: key}
}

func (ca *testCA) leaf(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type seenRequest struct {
	proto  int
	host   string
	header http.Header
	path   string
	query  string
	body   string
}

type upstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []seenRequest
}

func (u *upstream) seen() []seenRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.reqs)
}

func startUpstream(t *testing.T, ca *testCA, host string, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, seenRequest{proto: r.ProtoMajor, host: r.Host, header: r.Header.Clone(), path: r.URL.EscapedPath(), query: r.URL.RawQuery, body: string(body)})
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	u.srv.EnableHTTP2 = true
	u.srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, host)}, NextProtos: []string{"h2", "http/1.1"}}
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

type harness struct {
	t      testing.TB
	proxy  *Proxy
	addr   string
	caPool *x509.CertPool
	dials  atomic.Int32
	uses   chan Use
}

func headerBinding(token func(context.Context) (string, error)) Binding {
	return Binding{
		ID:          "github",
		Hosts:       []string{boundHost},
		Placeholder: placeholder,
		Injects:     []Injection{bearerInjection},
		Token:       token,
	}
}

func basicBinding(token func(context.Context) (string, error)) Binding {
	return Binding{
		ID:          "git",
		Hosts:       []string{basicHost},
		Placeholder: placeholder,
		Injects:     []Injection{basicInjection},
		Token:       token,
	}
}

func staticToken(calls *atomic.Int32) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		if calls != nil {
			calls.Add(1)
		}
		return realToken, nil
	}
}

func startProxy(t testing.TB, cfg Config, roots *x509.CertPool, routes map[string]string) *harness {
	t.Helper()
	h := &harness{t: t, uses: make(chan Use, 64)}
	cfg.UpstreamRoots = roots
	if routes != nil {
		cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			h.dials.Add(1)
			target, ok := routes[addr]
			if !ok {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		}
	}
	cfg.Record = func(u Use) {
		if strings.Contains(u.Err, realToken) {
			t.Errorf("Use.Err contains the token: %q", u.Err)
		}
		h.uses <- u
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(ln) }()
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v after Close", err)
		}
	})
	h.proxy, h.addr = p, ln.Addr().String()
	h.caPool = x509.NewCertPool()
	if !h.caPool.AppendCertsFromPEM(p.CACertPEM()) {
		t.Fatal("CACertPEM is not a PEM certificate")
	}
	return h
}

func (h *harness) nextUse() Use {
	h.t.Helper()
	select {
	case u := <-h.uses:
		return u
	case <-time.After(5 * time.Second):
		h.t.Fatal("no Use recorded")
		return Use{}
	}
}

func (h *harness) noUse() {
	h.t.Helper()
	select {
	case u := <-h.uses:
		h.t.Fatalf("unexpected Use %+v", u)
	case <-time.After(50 * time.Millisecond):
	}
}

func (h *harness) client(http2 bool, roots *x509.CertPool) *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: h.addr}),
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2: http2,
	}
	if !http2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (h *harness) connect(target string) (net.Conn, *bufio.Reader, int) {
	h.t.Helper()
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		h.t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return c, br, resp.StatusCode
}

func (h *harness) tlsTunnel(target, sni string, protos ...string) (*tls.Conn, error) {
	h.t.Helper()
	c, _, code := h.connect(target)
	if code != http.StatusOK {
		h.t.Fatalf("CONNECT %s: status %d", target, code)
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, RootCAs: h.caPool, NextProtos: protos})
	return tc, tc.Handshake()
}

func (h *harness) tunnelTransport(protos ...string) (*http.Transport, *atomic.Int32) {
	var n atomic.Int32
	tr := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			n.Add(1)
			return h.tlsTunnel(boundHost+":443", boundHost, protos...)
		},
		ForceAttemptHTTP2: slices.Contains(protos, "h2"),
	}
	h.t.Cleanup(tr.CloseIdleConnections)
	return tr, &n
}

func rawExchange(t *testing.T, c net.Conn, req string) (*http.Response, string) {
	t.Helper()
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestConnectRequestLine(t *testing.T) {
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, nil, map[string]string{})
	for _, tc := range []struct {
		line string
		want int
	}{
		{"GET http://api.bound.test/ HTTP/1.1\r\nHost: api.bound.test", http.StatusMethodNotAllowed},
		{"POST / HTTP/1.1\r\nHost: api.bound.test", http.StatusMethodNotAllowed},
		{"DELETE https://api.bound.test/x HTTP/1.1\r\nHost: api.bound.test", http.StatusMethodNotAllowed},
		{"CONNECT api.bound.test HTTP/1.1\r\nHost: api.bound.test", http.StatusBadRequest},
		{"CONNECT :443 HTTP/1.1\r\nHost: x", http.StatusBadRequest},
		{"CONNECT [::1:443 HTTP/1.1\r\nHost: x", http.StatusBadRequest},
		{"CONNECT api.bound.test:99999 HTTP/1.1\r\nHost: x", http.StatusBadRequest},
		{"CONNECT api.bound.test:44a HTTP/1.1\r\nHost: x", http.StatusBadRequest},
		{"CONNECT /api.bound.test:443 HTTP/1.1\r\nHost: x", http.StatusBadRequest},
		{"CONNECT api..bound.test:443 HTTP/1.1\r\nHost: x", http.StatusBadRequest},
		{"CONNECT api.bound.test:8443 HTTP/1.1\r\nHost: api.bound.test:8443", http.StatusForbidden},
		{"CONNECT API.Bound.Test.:80 HTTP/1.1\r\nHost: x", http.StatusForbidden},
		{"CONNECT api.bound.test:0443 HTTP/1.1\r\nHost: x", http.StatusForbidden},
	} {
		t.Run(tc.line[:strings.IndexByte(tc.line, '\r')], func(t *testing.T) {
			c, err := net.Dial("tcp", h.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			resp, _ := rawExchange(t, c, tc.line+"\r\n\r\n")
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusForbidden {
				u := h.nextUse()
				if u.BindingID != "github" || u.Method != http.MethodConnect || u.Status != http.StatusForbidden || u.Host != boundHost {
					t.Fatalf("Use %+v", u)
				}
			}
		})
	}
	if n := h.dials.Load(); n != 0 {
		t.Fatalf("%d upstream dials", n)
	}
}

func TestAuthorityChecks(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	routes := map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()}

	t.Run("SNI", func(t *testing.T) {
		h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, ca.pool, routes)
		for _, sni := range []string{otherHost, "api.bound.test.evil", "bound.test"} {
			c, _, _ := h.connect(boundHost + ":443")
			if err := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake(); err == nil {
				t.Fatalf("proxy completed a handshake for SNI %q", sni)
			}
			if u := h.nextUse(); u.Err != "tls handshake failed" || u.Method != http.MethodConnect {
				t.Fatalf("Use %+v", u)
			}
		}
		c, _, _ := h.connect(boundHost + ":443")
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		if err := tc.Handshake(); err == nil {
			t.Fatal("handshake without SNI succeeded")
		}
		h.nextUse()
		if n := h.dials.Load(); n != 0 || len(up.seen()) != 0 {
			t.Fatalf("dials %d, upstream requests %d", n, len(up.seen()))
		}
	})

	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run("Host/"+proto, func(t *testing.T) {
			h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, ca.pool, routes)
			tr, tunnels := h.tunnelTransport(proto)
			before := len(up.seen())
			for _, tc := range []struct {
				host string
				want int
			}{
				{boundHost, http.StatusOK},
				{otherHost, http.StatusMisdirectedRequest},
				{boundHost + ":8443", http.StatusMisdirectedRequest},
				{"API.Bound.Test.:443", http.StatusOK},
				{"api.bound.test.evil", http.StatusMisdirectedRequest},
				{boundHost + ":0443", http.StatusMisdirectedRequest},
				{"[::1]:443", http.StatusMisdirectedRequest},
			} {
				req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/x", nil)
				req.Host = tc.host
				req.Header.Set("Authorization", "Bearer "+placeholder)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					t.Fatalf("%s: %v", tc.host, err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != tc.want {
					t.Fatalf("Host %q: status %d, want %d", tc.host, resp.StatusCode, tc.want)
				}
				if wantMajor := map[string]int{"h2": 2, "http/1.1": 1}[proto]; resp.ProtoMajor != wantMajor {
					t.Fatalf("client proto %d", resp.ProtoMajor)
				}
				u := h.nextUse()
				if u.Status != tc.want || u.Injected != (tc.want == http.StatusOK) {
					t.Fatalf("Host %q: Use %+v", tc.host, u)
				}
			}
			if got := len(up.seen()) - before; got != 2 {
				t.Fatalf("upstream saw %d requests, want 2", got)
			}
			for _, r := range up.seen()[before:] {
				if r.host != boundHost || r.header.Get("Authorization") != "Bearer "+realToken {
					t.Fatalf("upstream saw host %q auth %q", r.host, r.header.Get("Authorization"))
				}
			}
			if proto == "h2" && tunnels.Load() != 1 {
				t.Fatalf("h2 requests used %d tunnels, want 1", tunnels.Load())
			}
		})
	}

	t.Run("absolute-form", func(t *testing.T) {
		h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, ca.pool, routes)
		tc, err := h.tlsTunnel(boundHost+":443", boundHost, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		before := len(up.seen())
		resp, _ := rawExchange(t, tc, "GET https://other.test/x HTTP/1.1\r\nHost: api.bound.test\r\nAuthorization: Bearer "+placeholder+"\r\n\r\n")
		if resp.StatusCode != http.StatusMisdirectedRequest || len(up.seen()) != before {
			t.Fatalf("status %d, upstream requests %d", resp.StatusCode, len(up.seen())-before)
		}
	})
}

func TestAuthorityMatchesHostHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = boundHost
	r.URL.Host = ""
	if !authorityMatches(boundHost, r) {
		t.Fatal("matching request refused")
	}
	r.Header.Set("Host", otherHost)
	if authorityMatches(boundHost, r) {
		t.Fatal("h2 request with :authority bound and Host header other accepted")
	}
}

func TestInjection(t *testing.T) {
	ca := newTestCA(t)
	upBound := startUpstream(t, ca, boundHost, nil)
	upBasic := startUpstream(t, ca, basicHost, nil)
	routes := map[string]string{
		boundHost + ":443": upBound.srv.Listener.Addr().String(),
		basicHost + ":443": upBasic.srv.Listener.Addr().String(),
	}
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	for _, tc := range []struct {
		name     string
		host     string
		auth     []string
		other    string
		query    string
		body     string
		wantAuth []string
		injected bool
	}{
		{name: "bearer", host: boundHost, auth: []string{"Bearer " + placeholder}, wantAuth: []string{"Bearer " + realToken}, injected: true},
		{name: "bearer wrong case prefix", host: boundHost, auth: []string{"bearer " + placeholder}, wantAuth: []string{"bearer " + placeholder}},
		{name: "bearer extra text", host: boundHost, auth: []string{"Bearer " + placeholder + " x"}, wantAuth: []string{"Bearer " + placeholder + " x"}},
		{name: "client credential kept", host: boundHost, auth: []string{"Bearer client-own"}, wantAuth: []string{"Bearer client-own"}},
		{name: "no header", host: boundHost},
		{name: "client copy dropped", host: boundHost, auth: []string{"Bearer client-own", "Bearer " + placeholder}, wantAuth: []string{"Bearer " + realToken}, injected: true},
		{name: "placeholder elsewhere only", host: boundHost, other: placeholder, query: "k=" + placeholder, body: "b=" + placeholder},
		{name: "placeholder elsewhere and declared", host: boundHost, auth: []string{"Bearer " + placeholder}, other: "x " + placeholder, query: "k=" + placeholder, body: placeholder, wantAuth: []string{"Bearer " + realToken}, injected: true},
		{name: "basic", host: basicHost, auth: []string{basic(basicUser, placeholder)}, wantAuth: []string{basic(basicUser, realToken)}, injected: true},
		{name: "basic lower-case scheme", host: basicHost, auth: []string{"basic " + base64.StdEncoding.EncodeToString([]byte(basicUser+":"+placeholder))}, wantAuth: []string{basic(basicUser, realToken)}, injected: true},
		{name: "basic other user", host: basicHost, auth: []string{basic("someone", placeholder)}, wantAuth: []string{basic("someone", placeholder)}},
		{name: "basic placeholder as user", host: basicHost, auth: []string{basic(placeholder, "x")}, wantAuth: []string{basic(placeholder, "x")}},
		{name: "basic bearer form", host: basicHost, auth: []string{"Bearer " + placeholder}, wantAuth: []string{"Bearer " + placeholder}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(&calls)), basicBinding(staticToken(&calls))}}, ca.pool, routes)
			target := "https://" + tc.host + "/path"
			if tc.query != "" {
				target += "?" + tc.query
			}
			req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(tc.body))
			req.Header["Authorization"] = tc.auth
			if tc.other != "" {
				req.Header.Set("X-Other", tc.other)
			}
			resp, err := h.client(false, h.caPool).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			up := map[string]*upstream{boundHost: upBound, basicHost: upBasic}[tc.host]
			seen := up.seen()
			got := seen[len(seen)-1]
			if a := got.header.Values("Authorization"); !slices.Equal(a, tc.wantAuth) {
				t.Fatalf("upstream Authorization %q, want %q", a, tc.wantAuth)
			}
			if got.header.Get("X-Other") != tc.other || got.query != tc.query || got.body != tc.body {
				t.Fatalf("upstream X-Other %q query %q body %q", got.header.Get("X-Other"), got.query, got.body)
			}
			wantCalls := int32(0)
			if tc.injected {
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Fatalf("Token called %d times", calls.Load())
			}
			u := h.nextUse()
			wantID := map[string]string{boundHost: "github", basicHost: "git"}[tc.host]
			if u.BindingID != wantID || u.Host != tc.host || u.Method != http.MethodPost || u.Path != "/path" ||
				u.Injected != tc.injected || u.Status != http.StatusOK || u.Err != "" || time.Since(u.At) > time.Minute {
				t.Fatalf("Use %+v", u)
			}
		})
	}
}

func TestBindingInjectionForms(t *testing.T) {
	ca := newTestCA(t)
	var calls atomic.Int32
	b := headerBinding(staticToken(&calls))
	b.Hosts = []string{basicHost, boundHost}
	b.Injects = []Injection{basicInjection, tokenInjection, bearerInjection}
	routes := map[string]string{}
	for _, host := range b.Hosts {
		up := startUpstream(t, ca, host, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, r.Header.Get("Authorization"))
		})
		routes[host+":443"] = up.srv.Listener.Addr().String()
	}
	h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, routes)
	client := h.client(false, h.caPool)
	for _, host := range b.Hosts {
		for _, tc := range []struct{ name, input, want string }{
			{"git", "Basic " + b64(basicUser+":"+placeholder), "Basic " + b64(basicUser+":"+realToken)},
			{"gh", "token " + placeholder, "token " + realToken},
			{"script", "Bearer " + placeholder, "Bearer " + realToken},
			{"lowercase bearer", "bearer " + placeholder, "bearer " + placeholder},
			{"extra space", "token  " + placeholder, "token  " + placeholder},
			{"other basic user", "Basic " + b64("other:"+placeholder), "Basic " + b64("other:"+placeholder)},
		} {
			t.Run(host+"/"+tc.name, func(t *testing.T) {
				before := calls.Load()
				req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
				req.Header.Set("Authorization", tc.input)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || string(body) != tc.want {
					t.Fatalf("upstream received %q, want %q (read error %v)", body, tc.want, err)
				}
				injected := tc.input != tc.want
				if u := h.nextUse(); u.Injected != injected || u.Status != http.StatusOK {
					t.Fatalf("Use %+v", u)
				}
				if !injected && calls.Load() != before {
					t.Fatal("fetched a token for an undeclared location")
				}
			})
		}
	}
}

func TestHopHeadersNotForwarded(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	tc, err := h.tlsTunnel(boundHost+":443", boundHost, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := rawExchange(t, tc, "GET /x HTTP/1.1\r\nHost: api.bound.test\r\n"+
		"Proxy-Authorization: Basic cHJveHk6cHc=\r\nProxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\n"+
		"Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nTE: gzip\r\nUpgrade: h2c\r\nX-Kept: yes\r\n\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := up.seen()[0].header
	for _, k := range []string{"Proxy-Authorization", "Proxy-Connection", "Keep-Alive", "X-Hop", "Te", "Upgrade"} {
		if v, ok := got[k]; ok {
			t.Errorf("upstream received %s: %q", k, v)
		}
	}
	if got.Get("X-Kept") != "yes" {
		t.Fatal("end-to-end header dropped")
	}
}

func TestSpliceUnboundHost(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, otherHost, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "echo:"+r.Header.Get("Authorization"))
	})
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, nil, map[string]string{otherHost + ":443": up.srv.Listener.Addr().String()})
	req, _ := http.NewRequest(http.MethodPost, "https://"+otherHost+"/echo", strings.NewReader("ping"))
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := h.client(true, ca.pool).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "echo:Bearer "+placeholder {
		t.Fatalf("body %q", body)
	}
	if !resp.TLS.PeerCertificates[0].Equal(up.srv.Certificate()) {
		t.Fatal("client did not see the upstream's own certificate")
	}
	if got := up.seen()[0]; got.body != "ping" || got.proto != 2 {
		t.Fatalf("upstream saw body %q proto %d", got.body, got.proto)
	}
	h.noUse()

	if _, err := h.client(false, h.caPool).Get("https://" + otherHost + "/"); err == nil {
		t.Fatal("client trusting only the proxy CA accepted the spliced upstream")
	}
}

func TestTokenErrorAndGuardRefusal(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)

	t.Run("token error", func(t *testing.T) {
		b := headerBinding(func(context.Context) (string, error) { return "", errors.New("vault sealed") })
		h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
		req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/x", nil)
		req.Header.Set("Authorization", "Bearer "+placeholder)
		resp, err := h.client(false, h.caPool).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway || h.dials.Load() != 0 || len(up.seen()) != 0 {
			t.Fatalf("status %d dials %d upstream %d", resp.StatusCode, h.dials.Load(), len(up.seen()))
		}
		if u := h.nextUse(); u.Status != http.StatusBadGateway || u.Err != "token unavailable" || u.Injected {
			t.Fatalf("Use %+v", u)
		}
	})

	t.Run("guard refuses bound host", func(t *testing.T) {
		b := headerBinding(staticToken(nil))
		b.Hosts = []string{"localhost"}
		h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, nil)
		req, _ := http.NewRequest(http.MethodGet, "https://localhost/x", nil)
		req.Header.Set("Authorization", "Bearer "+placeholder)
		resp, err := h.client(false, h.caPool).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if u := h.nextUse(); u.Status != http.StatusBadGateway || u.Err != "dial denied by address guard" || u.Injected {
			t.Fatalf("Use %+v", u)
		}
	})

	t.Run("guard refuses splice", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		accepted := make(chan struct{}, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				accepted <- struct{}{}
				_ = c.Close()
			}
		}()
		h := startProxy(t, Config{DenyPrefixes: nil}, nil, nil)
		if _, _, code := h.connect(ln.Addr().String()); code != http.StatusBadGateway {
			t.Fatalf("status %d", code)
		}
		select {
		case <-accepted:
			t.Fatal("denied address was dialled")
		case <-time.After(100 * time.Millisecond):
		}
	})
}

func TestUpstreamCertificateVerified(t *testing.T) {
	trusted, untrusted := newTestCA(t), newTestCA(t)
	for name, up := range map[string]*upstream{
		"unknown CA": startUpstream(t, untrusted, boundHost, nil),
		"wrong name": startUpstream(t, trusted, otherHost, nil),
	} {
		t.Run(name, func(t *testing.T) {
			h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, trusted.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
			req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/x", nil)
			req.Header.Set("Authorization", "Bearer "+placeholder)
			resp, err := h.client(false, h.caPool).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway || len(up.seen()) != 0 {
				t.Fatalf("status %d, upstream requests %d", resp.StatusCode, len(up.seen()))
			}
			if u := h.nextUse(); u.Err != "upstream certificate rejected" || u.Injected {
				t.Fatalf("Use %+v", u)
			}
		})
	}
}

func TestUpstreamErrorTextNeverCarriesToken(t *testing.T) {
	const pathToken = "api/webhooks/test/secret-example"
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	ca := newTestCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, boundHost)}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nBroken header "+r.Header.Get("Authorization")+" "+r.URL.EscapedPath()+"\r\n\r\n")
			}()
		}
	}()
	path := pathBinding(pathToken)
	path.ID = "webhook"
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil)), path}}, ca.pool, map[string]string{boundHost + ":443": ln.Addr().String()})
	req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/"+placeholder, nil)
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := h.client(false, h.caPool).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), realToken) || strings.Contains(string(body), pathToken) {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	u := h.nextUse()
	visible := fmt.Sprint(u, resp.Header)
	if u.Err != "upstream request failed" || u.Path != "/"+placeholder || !u.Injected || strings.Contains(visible, pathToken) || strings.Contains(visible, realToken) {
		t.Fatalf("Use %+v", u)
	}
	log.SetOutput(previous)
	if strings.Contains(logs.String(), pathToken) || strings.Contains(logs.String(), realToken) {
		t.Error("proxy logged a credential")
	}
}

func TestScanResponses(t *testing.T) {
	ca := newTestCA(t)
	var acceptEnc sync.Map
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		acceptEnc.Store(r.URL.Path, r.Header.Get("Accept-Encoding"))
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if secret == "" || secret == "client-own" {
			secret = realToken
		}
		switch r.URL.Path {
		case "/header":
			w.Header().Set("X-Echo", "token "+secret)
		case "/body":
			_, _ = io.WriteString(w, `{"token":"`+secret+`"}`)
		case "/encodings":
			_, _ = io.WriteString(w, secret+"|"+b64(basicUser+":"+secret)+"|"+b64("other:"+secret))
		case "/split":
			_, _ = io.WriteString(w, "a"+secret[:7])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			_, _ = io.WriteString(w, secret[7:]+"b")
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = io.WriteString(zw, "z:"+secret)
			_ = zw.Close()
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			_, _ = io.WriteString(w, "not really brotli")
		case "/trailer":
			w.Header().Set("Trailer", "X-Tail")
			_, _ = io.WriteString(w, "t")
			w.Header().Set("X-Tail", secret)
		}
	})
	upBasic := startUpstream(t, ca, basicHost, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"headers":{"Authorization":"`+r.Header.Get("Authorization")+`"}}`)
	})
	routes := map[string]string{
		boundHost + ":443": up.srv.Listener.Addr().String(),
		basicHost + ":443": upBasic.srv.Listener.Addr().String(),
	}
	b := headerBinding(staticToken(nil))
	b.Injects = append(b.Injects, basicInjection, Injection{BasicUser: "other"})
	h := startProxy(t, Config{Bindings: []Binding{b, basicBinding(staticToken(nil))}, ScanResponses: true}, ca.pool, routes)
	for _, http2 := range []bool{false, true} {
		client := h.client(http2, h.caPool)
		get := func(path, auth string) (*http.Response, string) {
			t.Helper()
			req, _ := http.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", auth)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			h.nextUse()
			return resp, string(body)
		}
		bearer := "Bearer " + placeholder
		for _, tc := range []struct {
			path, auth, want string
		}{
			{"/body", bearer, `{"token":"` + placeholder + `"}`},
			{"/encodings", bearer, placeholder + "|" + b64(basicUser+":"+placeholder) + "|" + b64("other:"+placeholder)},
			{"/split", bearer, "a" + placeholder + "b"},
			{"/gzip", bearer, "z:" + placeholder},
			{"/body", "Bearer client-own", `{"token":"` + placeholder + `"}`},
		} {
			resp, body := get("https://"+boundHost+tc.path, tc.auth)
			if resp.StatusCode != http.StatusOK || body != tc.want || resp.Header.Get("Content-Encoding") != "" {
				t.Fatalf("%s: status %d body %q encoding %q", tc.path, resp.StatusCode, body, resp.Header.Get("Content-Encoding"))
			}
			if v, _ := acceptEnc.Load(tc.path); v != "identity" {
				t.Fatalf("%s: upstream Accept-Encoding %q", tc.path, v)
			}
		}
		resp, _ := get("https://"+boundHost+"/header", bearer)
		if resp.Header.Get("X-Echo") != "token "+placeholder {
			t.Fatalf("X-Echo %q", resp.Header.Get("X-Echo"))
		}
		resp, body := get("https://"+boundHost+"/trailer", bearer)
		if body != "t" || resp.Trailer.Get("X-Tail") != placeholder {
			t.Fatalf("trailer %q", resp.Trailer.Get("X-Tail"))
		}
		if resp, _ := get("https://"+boundHost+"/br", bearer); resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("br: status %d", resp.StatusCode)
		}
		basicPH := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUser+":"+placeholder))
		if _, body := get("https://"+basicHost+"/headers", basicPH); body != `{"headers":{"Authorization":"`+basicPH+`"}}` {
			t.Fatalf("basic echo %q", body)
		}
	}
}

func TestScanUsesOwnTokenAfterRotation(t *testing.T) {
	ca := newTestCA(t)
	release := make(chan struct{})
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			<-release
		}
		_, _ = io.WriteString(w, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	})
	var issued atomic.Int32
	b := headerBinding(func(context.Context) (string, error) {
		return fmt.Sprintf("rotating-token-%03d", issued.Add(1)), nil
	})
	h := startProxy(t, Config{Bindings: []Binding{b}, ScanResponses: true}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	get := func(path string) string {
		req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+path, nil)
		req.Header.Set("Authorization", "Bearer "+placeholder)
		resp, err := h.client(false, h.caPool).Do(req)
		if err != nil {
			t.Error(err)
			return ""
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(body)
	}
	first := make(chan string, 1)
	go func() { first <- get("/first") }()
	for issued.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	for range recentTokens + 1 {
		if body := get("/later"); body != placeholder {
			t.Fatalf("later body %q", body)
		}
	}
	close(release)
	if body := <-first; body != placeholder {
		t.Fatalf("first response body %q after %d later tokens", body, recentTokens+1)
	}
}

func TestScanRedactsInterimResponses(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Link", "</x?k="+secret+">; rel=preload")
		w.Header().Set("X-"+secret, "1")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Del("X-" + secret)
		_, _ = io.WriteString(w, "done")
	})
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}, ScanResponses: true}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	for _, http2 := range []bool{false, true} {
		var interim []http.Header
		trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, hdr textproto.MIMEHeader) error {
			interim = append(interim, http.Header(hdr).Clone())
			return nil
		}}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "https://"+boundHost+"/", nil)
		req.Header.Set("Authorization", "Bearer "+placeholder)
		resp, err := h.client(http2, h.caPool).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		h.nextUse()
		if len(interim) != 1 {
			t.Fatalf("http2=%v: %d interim responses", http2, len(interim))
		}
		for name, vs := range interim[0] {
			if strings.Contains(strings.ToLower(name+strings.Join(vs, " ")), realToken) {
				t.Fatalf("http2=%v: interim header %s: %q kept the token", http2, name, vs)
			}
		}
		if !strings.Contains(interim[0].Get("Link"), placeholder) {
			t.Fatalf("http2=%v: interim Link %q", http2, interim[0].Get("Link"))
		}
	}
}

func TestWebSocketUpgrade(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+realToken || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "bad handshake", http.StatusUnauthorized)
			return
		}
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		_ = brw.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(brw, buf); err == nil {
			_, _ = c.Write(append([]byte("echo:"), buf...))
		}
	})
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}, ScanResponses: true}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	tc, err := h.tlsTunnel(boundHost+":443", boundHost, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: api.bound.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer "+placeholder+"\r\n\r\n")
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, _ = io.WriteString(tc, "ping")
	got := make([]byte, 9)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "echo:ping" {
		t.Fatalf("read %q: %v", got, err)
	}
	if u := h.nextUse(); !u.Injected || u.Status != http.StatusSwitchingProtocols {
		t.Fatalf("Use %+v", u)
	}
}

func TestNewValidation(t *testing.T) {
	ok := headerBinding(staticToken(nil))
	for name, mutate := range map[string]func(*Binding){
		"no ID":            func(b *Binding) { b.ID = "" },
		"no hosts":         func(b *Binding) { b.Hosts = nil },
		"upper-case host":  func(b *Binding) { b.Hosts = []string{"API.bound.test"} },
		"host with port":   func(b *Binding) { b.Hosts = []string{"api.bound.test:443"} },
		"trailing dot":     func(b *Binding) { b.Hosts = []string{"api.bound.test."} },
		"IP host":          func(b *Binding) { b.Hosts = []string{"203.0.113.7"} },
		"no placeholder":   func(b *Binding) { b.Placeholder = "" },
		"no token":         func(b *Binding) { b.Token = nil },
		"no forms":         func(b *Binding) { b.Injects = nil },
		"empty form":       func(b *Binding) { b.Injects = []Injection{{}} },
		"path with header": func(b *Binding) { b.Injects = []Injection{{Path: true, Header: "X-Key"}} },
		"path with basic":  func(b *Binding) { b.Injects = []Injection{{Path: true, BasicUser: "u"}} },
		"path with prefix": func(b *Binding) { b.Injects = []Injection{{Path: true, Prefix: "Bearer "}} },
		"repeated path":    func(b *Binding) { b.Injects = []Injection{{Path: true}, {Path: true}} },
		"both injections":  func(b *Binding) { b.Injects = append(b.Injects, Injection{Header: "Authorization", BasicUser: "u"}) },
		"basic with colon": func(b *Binding) { b.Injects = []Injection{{BasicUser: "a:b"}} },
		"repeated form":    func(b *Binding) { b.Injects = append(b.Injects, bearerInjection) },
		"repeated header form with different casing": func(b *Binding) {
			b.Injects = append(b.Injects, Injection{Header: "authorization", Prefix: "Bearer "})
		},
	} {
		b := ok
		mutate(&b)
		if _, err := New(Config{Bindings: []Binding{b}}); err == nil {
			t.Errorf("%s: New accepted the binding", name)
		}
	}
	twice := ok
	twice.Hosts = []string{boundHost, boundHost}
	if _, err := New(Config{Bindings: []Binding{twice}}); err == nil {
		t.Error("New accepted a binding that lists a host twice")
	}
	shared := ok
	shared.ID, shared.Placeholder = "other", placeholder+"-other"
	p, err := New(Config{Bindings: []Binding{ok, shared}})
	if err != nil {
		t.Fatalf("New refused two bindings on one host: %v", err)
	}
	defer func() { _ = p.Close() }()
	if len(p.impl.ca.leaves) != 1 {
		t.Fatalf("%d leaves for one shared host", len(p.impl.ca.leaves))
	}
}

func TestSharedHostBindings(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization")+"|"+r.Header.Get("X-Api-Key"))
	})
	routes := map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()}
	token := func(v string) func(context.Context) (string, error) {
		return func(context.Context) (string, error) { return v, nil }
	}
	bindings := []Binding{
		{ID: "a", Hosts: []string{boundHost}, Placeholder: "ph-a", Injects: []Injection{bearerInjection}, Token: token("real-a-41d2")},
		{ID: "b", Hosts: []string{boundHost}, Placeholder: "ph-b", Injects: []Injection{bearerInjection, keyInjection}, Token: token("real-b-9c41")},
		{ID: "c", Hosts: []string{boundHost}, Placeholder: "ph-c", Injects: []Injection{bearerInjection}, Token: token("real-c-7f3a")},
	}
	for _, tc := range []struct {
		name              string
		auth, key         string
		auth2             []string
		wantAuth, wantKey string
		wantBody, wantID  string
		injected          bool
	}{
		{name: "different headers, one placeholder", key: "ph-b", wantKey: "real-b-9c41", wantBody: "|ph-b", wantID: "b", injected: true},
		{name: "same header picks the exact match", auth: "Bearer ph-c", wantAuth: "Bearer real-c-7f3a", wantBody: "Bearer ph-c|", wantID: "c", injected: true},
		{name: "request carrying both", auth: "Bearer ph-a", key: "ph-b", wantAuth: "Bearer real-a-41d2", wantKey: "real-b-9c41", wantBody: "Bearer ph-a|ph-b", wantID: "a,b", injected: true},
		{name: "first matching form wins", auth: "Bearer ph-b", key: "ph-b", wantAuth: "Bearer real-b-9c41", wantKey: "ph-b", wantBody: "Bearer ph-b|ph-b", wantID: "b", injected: true},
		{name: "first matching form already claimed", auth2: []string{"Bearer ph-a", "Bearer ph-b"}, key: "ph-b", wantAuth: "Bearer real-a-41d2", wantKey: "ph-b", wantBody: "Bearer ph-a|ph-b", wantID: "a", injected: true},
		{name: "same header twice, first binding wins", auth2: []string{"Bearer ph-a", "Bearer ph-c"}, wantAuth: "Bearer real-a-41d2", wantBody: "Bearer ph-a|", wantID: "a", injected: true},
		{name: "no placeholder", auth: "Bearer own", wantAuth: "Bearer own", wantBody: "Bearer own|", wantID: "a,b,c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startProxy(t, Config{Bindings: bindings, ScanResponses: true}, ca.pool, routes)
			req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/path", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.key != "" {
				req.Header.Set("X-Api-Key", tc.key)
			}
			if tc.auth2 != nil {
				req.Header["Authorization"] = tc.auth2
			}
			resp, err := h.client(false, h.caPool).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			seen := up.seen()
			got := seen[len(seen)-1]
			if a := got.header.Values("Authorization"); (tc.wantAuth == "" && len(a) != 0) || (tc.wantAuth != "" && (len(a) != 1 || a[0] != tc.wantAuth)) || got.header.Get("X-Api-Key") != tc.wantKey {
				t.Fatalf("upstream Authorization %q X-Api-Key %q", got.header.Get("Authorization"), got.header.Get("X-Api-Key"))
			}
			if string(body) != tc.wantBody {
				t.Fatalf("client body %q, want %q", body, tc.wantBody)
			}
			if u := h.nextUse(); u.BindingID != tc.wantID || u.Injected != tc.injected || u.Status != http.StatusOK {
				t.Fatalf("Use %+v", u)
			}
		})
	}
}

func TestCertificateAuthority(t *testing.T) {
	p, err := New(Config{Bindings: []Binding{headerBinding(staticToken(nil)), basicBinding(staticToken(nil))}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	block, _ := pem.Decode(p.CACertPEM())
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Subject.CommonName != "hostbound CA" {
		t.Fatalf("CA common name = %q", ca.Subject.CommonName)
	}
	pub, isECDSA := ca.PublicKey.(*ecdsa.PublicKey)
	if !ca.IsCA || !isECDSA || pub.Curve != elliptic.P256() {
		t.Fatalf("CA IsCA=%v key %T", ca.IsCA, ca.PublicKey)
	}
	if !slices.Equal(slices.Sorted(func(yield func(string) bool) {
		for h := range p.impl.ca.leaves {
			if !yield(h) {
				return
			}
		}
	}), []string{boundHost, basicHost}) {
		t.Fatal("leaves are not exactly the bound hosts")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for host, leaf := range p.impl.ca.leaves {
		cert, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}
}

func TestCloseStopsServeAndTunnels(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, otherHost, nil)
	p, err := New(Config{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, up.srv.Listener.Addr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(ln) }()
	h := &harness{t: t, addr: ln.Addr().String()}
	c, br, code := h.connect(otherHost + ":443")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("tunnel still open after Close: %v", err)
	}
}

func pathBinding(token string) Binding {
	return Binding{
		ID: "path", Hosts: []string{boundHost}, Placeholder: placeholder, Injects: []Injection{{Path: true}},
		Token: func(context.Context) (string, error) { return token, nil },
	}
}

func TestPathInjection(t *testing.T) {
	const tok = "12345:Example_-.~9"
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	for _, tc := range []struct {
		name, target, token, wantPath, wantErr string
	}{
		{"telegram", "/bot" + placeholder + "/sendMessage", tok, "/bot" + tok + "/sendMessage", ""},
		{"discord", "/" + placeholder, "api/webhooks/id/example", "/api/webhooks/id/example", ""},
		{"all literal occurrences", "/a%3ab/" + placeholder + "/" + placeholder, tok, "/a%3ab/" + tok + "/" + tok, ""},
		{"query only", "/x?q=" + placeholder, tok, "/x", ""},
		{"path and query", "/" + placeholder + "?q=" + placeholder, tok, "/" + tok, ""},
		{"encoded placeholder", "/%70" + placeholder[1:], tok, "", "encoded path placeholder"},
		{"literal and partly encoded", "/" + placeholder + "/p%72" + placeholder[2:], tok, "", "encoded path placeholder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startProxy(t, Config{Bindings: []Binding{pathBinding(tc.token)}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
			before := len(up.seen())
			req, err := http.NewRequest(http.MethodGet, "https://"+boundHost+tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+placeholder)
			resp, err := h.client(false, h.caPool).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			u := h.nextUse()
			if u.Path != req.URL.EscapedPath() || u.Err != tc.wantErr || u.Injected != strings.Contains(tc.wantPath, tc.token) {
				t.Fatalf("Use %+v", u)
			}
			seen := up.seen()[before:]
			if tc.wantErr != "" {
				if resp.StatusCode != http.StatusBadRequest || len(seen) != 0 {
					t.Fatalf("status %d, forwarded %d requests", resp.StatusCode, len(seen))
				}
				return
			}
			if len(seen) != 1 || seen[0].path != tc.wantPath || seen[0].query != req.URL.RawQuery || seen[0].header.Get("Authorization") != "Bearer "+placeholder {
				t.Fatalf("forwarded %+v, want path %q", seen, tc.wantPath)
			}
		})
	}
}

func TestUnsafePathToken(t *testing.T) {
	for _, c := range []string{"%", "?", "#", " ", "\r", "\n", "\\", "@", "+", "&", ";", "=", "é"} {
		t.Run(fmt.Sprintf("%x", c), func(t *testing.T) {
			h := startProxy(t, Config{Bindings: []Binding{pathBinding("example" + c + "token")}}, nil, map[string]string{})
			resp, err := h.client(false, h.caPool).Get("https://" + boundHost + "/" + placeholder)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			u := h.nextUse()
			if u.Err != "invalid path token" || u.Injected || u.Path != "/"+placeholder || resp.StatusCode != http.StatusBadGateway || h.dials.Load() != 0 {
				t.Fatalf("Use %+v, dials %d", u, h.dials.Load())
			}
		})
	}
}

func TestPathFormOrder(t *testing.T) {
	const grant = "granted-command"
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	path := Injection{Path: true}
	for _, tc := range []struct {
		name                 string
		forms                []Injection
		path, header         string
		wantPath, wantHeader string
	}{
		{"path first", []Injection{path, bearerInjection}, grant, placeholder, realToken, placeholder},
		{"header first", []Injection{bearerInjection, path}, grant, placeholder, grant, realToken},
		{"path only matches", []Injection{bearerInjection, path}, grant, "other", realToken, "other"},
		{"header only matches", []Injection{path, bearerInjection}, "other", grant, "other", realToken},
		{"grant in later header", []Injection{path, bearerInjection}, placeholder, grant, realToken, grant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := pathBinding(realToken)
			b.Injects = tc.forms
			h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
			revoke, err := h.proxy.Grant(b.ID, grant)
			if err != nil {
				t.Fatal(err)
			}
			defer revoke()
			req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/"+tc.path, nil)
			req.Header.Set("Authorization", bearerInjection.value(tc.header))
			before := len(up.seen())
			resp, err := h.client(false, h.caPool).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if seen := up.seen()[before:]; len(seen) != 1 || seen[0].path != "/"+tc.wantPath || seen[0].header.Get("Authorization") != bearerInjection.value(tc.wantHeader) {
				t.Fatalf("upstream requests %+v", seen)
			}
			if u := h.nextUse(); !u.Granted || !u.Injected || u.Path != "/"+tc.path {
				t.Fatalf("Use %+v", u)
			}
		})
	}
}

func TestOverlappingPathPlaceholders(t *testing.T) {
	for _, tc := range []struct {
		name, base, other, grant, path string
	}{
		{"self", "aba", "", "", "/ababa"},
		{"identical bindings", "abc", "abc", "", "/abc"},
		{"partial bindings", "abc", "bcd", "", "/abcd"},
		{"grant contains base", "abc", "", "zabc", "/zabc"},
		{"grant and other binding", "unused", "bcd", "abc", "/abcd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := pathBinding(realToken)
			b.Placeholder = tc.base
			bs := []Binding{b}
			if tc.other != "" {
				other := pathBinding("other-token")
				other.ID, other.Placeholder = "other", tc.other
				bs = append(bs, other)
			}
			h := startProxy(t, Config{Bindings: bs}, nil, map[string]string{})
			if tc.grant != "" {
				revoke, err := h.proxy.Grant(b.ID, tc.grant)
				if err != nil {
					t.Fatal(err)
				}
				defer revoke()
			}
			resp, err := h.client(true, h.caPool).Get("https://" + boundHost + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if u := h.nextUse(); resp.StatusCode != http.StatusBadRequest || u.Err != "overlapping path placeholders" || u.Injected || h.dials.Load() != 0 {
				t.Fatalf("status %d, Use %+v, dials %d", resp.StatusCode, u, h.dials.Load())
			}
		})
	}
}

func TestDistinctPathPresentations(t *testing.T) {
	b := pathBinding(realToken)
	b.Check = func(*http.Request, string) error {
		t.Error("Check received only one of the request's two distinct placeholders")
		return nil
	}
	h := startProxy(t, Config{Bindings: []Binding{b}}, nil, map[string]string{})
	const grant = "command-grant"
	revoke, err := h.proxy.Grant(b.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	resp, err := h.client(true, h.caPool).Get("https://" + boundHost + "/" + grant + "/" + b.Placeholder)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if u := h.nextUse(); u.Err != "multiple distinct path placeholders for binding" || u.Injected || resp.StatusCode != http.StatusBadRequest || h.dials.Load() != 0 {
		t.Fatalf("HTTP %d, Use %+v, dials %d", resp.StatusCode, u, h.dials.Load())
	}
}

func TestPathGrant(t *testing.T) {
	const grant = "command-grant"
	b := pathBinding(realToken)
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	revoke, err := h.proxy.Grant(b.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	client := h.client(true, h.caPool)
	for _, tc := range []struct {
		path, want, reason string
		revoked            bool
	}{
		{"/" + grant + "/" + grant, "/" + realToken + "/" + realToken, "", false},
		{"/%63" + grant[1:], "", "encoded path placeholder", false},
		{"/" + grant, "/" + grant, "", true},
	} {
		if tc.revoked {
			revoke()
		}
		before := len(up.seen())
		resp, err := client.Get("https://" + boundHost + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		u := h.nextUse()
		if u.Err != tc.reason || u.Path != tc.path || u.Injected != strings.Contains(tc.want, realToken) {
			t.Fatalf("Use %+v for %q", u, tc.path)
		}
		seen := up.seen()[before:]
		if tc.reason != "" {
			if len(seen) != 0 || resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("forwarded encoded grant: status %d, upstream %+v", resp.StatusCode, seen)
			}
		} else if u.Granted != u.Injected || len(seen) != 1 || seen[0].path != tc.want {
			t.Fatalf("Use %+v, upstream %+v", u, seen)
		}
	}
}

func TestCheckPath(t *testing.T) {
	const grant = "command-grant"
	b := pathBinding(realToken)
	b.Token = func(context.Context) (string, error) {
		t.Error("Token called after refusal")
		return "", nil
	}
	b.Check = func(r *http.Request, presented string) error {
		want := "/bot" + presented + "/send"
		if r.URL.EscapedPath() != want || r.URL.Path != want || r.RequestURI != want {
			t.Errorf("Check got %q for URL %q and request target %q", presented, r.URL, r.RequestURI)
		}
		reason := "write refused for " + r.URL.EscapedPath()
		return &Refusal{Status: http.StatusForbidden, Reason: reason, Body: []byte(reason)}
	}
	h := startProxy(t, Config{Bindings: []Binding{b}}, nil, map[string]string{})
	revoke, err := h.proxy.Grant(b.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	client := h.client(true, h.caPool)
	for _, ph := range []string{b.Placeholder, grant} {
		resp, err := client.Get("https://" + boundHost + "/bot" + ph + "/send")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := "write refused for /bot" + ph + "/send"
		u := h.nextUse()
		if err != nil || string(body) != want || strings.Contains(fmt.Sprint(u, resp.Header, string(body), err), realToken) {
			t.Fatalf("refused response %+v, body %q, read error %v, Use %+v", resp.Header, body, err, u)
		}
		if u.Err != want || u.Injected || u.Granted != (ph == grant) || resp.StatusCode != http.StatusForbidden || h.dials.Load() != 0 {
			t.Fatalf("status %d, Use %+v, dials %d", resp.StatusCode, u, h.dials.Load())
		}
	}
}

func TestPathFailureRecords(t *testing.T) {
	const path = "/v4/spreadsheets/" + placeholder
	for _, tc := range []struct {
		name, token, prefix, reason string
		err                         error
		status                      int
	}{
		{"lookup error", realToken, path, "token unavailable", errors.New("cannot fetch " + realToken), http.StatusBadGateway},
		{"invalid token", realToken + "%", path, "invalid path token", nil, http.StatusBadGateway},
		{"after substitution", realToken, path, "injected path outside binding", nil, http.StatusForbidden},
		{"token adds dot segment", "../" + realToken, "/v4/spreadsheets", "injected path outside binding", nil, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := pathBinding(tc.token)
			b.PathPrefixes = []string{tc.prefix}
			b.Token = func(context.Context) (string, error) { return tc.token, tc.err }
			h := startProxy(t, Config{Bindings: []Binding{b}, ScanResponses: true}, nil, map[string]string{})
			resp, err := h.client(false, h.caPool).Get("https://" + boundHost + path)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			u := h.nextUse()
			if err != nil || strings.Contains(fmt.Sprint(u, resp.Status, resp.Header, string(body), err), realToken) {
				t.Fatalf("HTTP %s, headers %v, body %q, read error %v, Use %+v", resp.Status, resp.Header, body, err, u)
			}
			if resp.StatusCode != tc.status || u.Err != tc.reason || u.Path != path || u.Injected || h.dials.Load() != 0 {
				t.Fatalf("HTTP %d, Use %+v, dials %d", resp.StatusCode, u, h.dials.Load())
			}
		})
	}
}

func TestRevokePathGrant(t *testing.T) {
	const grant = "command-grant"
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	b := pathBinding(realToken)
	h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	revoke, err := h.proxy.Grant(b.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	resp, err := h.client(true, h.caPool).Get("https://" + boundHost + "/" + grant)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if seen := up.seen(); len(seen) != 1 || seen[0].path != "/"+realToken {
		t.Fatalf("upstream requests %+v", seen)
	}
	revoke()
	if u := h.nextUse(); !u.Granted || !u.Injected || u.Err != "grant revoked" || u.Path != "/"+grant {
		t.Fatalf("Use %+v", u)
	}
}

func TestPathPrefixes(t *testing.T) {
	const sheet = "/v4/spreadsheets/A"
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	for _, form := range []string{"header", "basic", "path"} {
		t.Run(form, func(t *testing.T) {
			b := headerBinding(staticToken(nil))
			if form == "path" {
				b = pathBinding(realToken)
			} else if form == "basic" {
				b.Injects = []Injection{basicInjection}
			}
			b.PathPrefixes = []string{"/other", sheet}
			h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
			client := h.client(true, h.caPool)
			for _, tc := range []struct {
				target string
				want   bool
			}{
				{sheet, true}, {sheet + "?fields=title", true}, {sheet + ":batchUpdate", true},
				{sheet + "/values/Sheet%201!A1:append", true}, {"/other/" + placeholder, true},
				{sheet + "/values/" + placeholder, true}, {sheet + ":" + placeholder, true},
				{sheet + "B/" + placeholder, false}, {sheet + "%3F/" + placeholder, false}, {"/before" + sheet + "/" + placeholder, false},
				{sheet + "/./" + placeholder, false}, {sheet + "/x/../" + placeholder, false}, {sheet + "/..", false},
				{sheet + "/x%2fy/" + placeholder, false}, {sheet + "/x%2Fy/" + placeholder, false},
				{sheet + "/x%2ey/" + placeholder, false}, {sheet + "/%2E/" + placeholder, false},
				{sheet + "/version.1/" + placeholder + "?q=%2F%2E", true},
			} {
				req, err := http.NewRequest(http.MethodGet, "https://"+boundHost+tc.target, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+placeholder)
				if form == "basic" {
					req.SetBasicAuth(basicUser, placeholder)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				u := h.nextUse()
				want := tc.want && (form != "path" || strings.Contains(req.URL.EscapedPath(), placeholder))
				seen := up.seen()
				got := seen[len(seen)-1]
				sent := strings.Contains(got.path, realToken) || bearerInjection.carries(got.header, realToken) || basicInjection.carries(got.header, realToken)
				if u.Path != req.URL.EscapedPath() || u.Injected != want || sent != want {
					t.Errorf("%s: injected %t, upstream path %q header %q, want %t", tc.target, u.Injected, got.path, got.header.Get("Authorization"), want)
				}
			}
		})
	}
}

func TestPathBeforeURLEscaping(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	b := pathBinding(realToken)
	b.PathPrefixes = []string{"/sheet"}
	h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	for _, tc := range []struct {
		target string
		status int
		reason string
	}{
		{"/sheet/|/%70" + placeholder[1:], http.StatusBadRequest, "encoded path placeholder"},
		{"/sheet/|/%2F/" + placeholder, http.StatusOK, ""},
		{"/sheet/|/%2e/" + placeholder, http.StatusOK, ""},
	} {
		c, err := h.tlsTunnel(boundHost+":443", boundHost, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		before := len(up.seen())
		resp, _ := rawExchange(t, c, "GET "+tc.target+" HTTP/1.1\r\nHost: "+boundHost+"\r\nConnection: close\r\n\r\n")
		c.Close()
		if u := h.nextUse(); resp.StatusCode != tc.status || u.Injected || u.Path != tc.target || u.Err != tc.reason {
			t.Fatalf("HTTP %d, Use %+v", resp.StatusCode, u)
		}
		seen := up.seen()[before:]
		if (tc.reason != "" && len(seen) != 0) || (tc.reason == "" && (len(seen) != 1 || strings.Contains(seen[0].path, realToken))) {
			t.Fatalf("upstream requests %+v for %q", seen, tc.target)
		}
	}
}

func TestPathRedirect(t *testing.T) {
	const token = "api/webhooks/123/test-token"
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+otherHost+r.URL.EscapedPath())
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, r.URL.EscapedPath())
	})
	other := startUpstream(t, ca, otherHost, nil)
	h := startProxy(t, Config{Bindings: []Binding{pathBinding(token)}, ScanResponses: true}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String(), otherHost + ":443": other.srv.Listener.Addr().String()})
	h.caPool.AddCert(ca.cert)
	client := h.client(false, h.caPool)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get("https://" + boundHost + "/" + placeholder)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	location := resp.Header.Get("Location")
	if err != nil || resp.StatusCode != http.StatusFound || string(body) != "/"+placeholder || location != "https://"+otherHost+"/"+placeholder || len(other.seen()) != 0 {
		t.Fatalf("redirect %d location %q body %q, err %v", resp.StatusCode, location, body, err)
	}
	if u := h.nextUse(); !u.Injected || u.Path != "/"+placeholder || up.seen()[0].path != "/"+token {
		t.Fatalf("request or record mismatch: %+v", u)
	}
	resp, err = client.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if seen := other.seen(); len(seen) != 1 || seen[0].path != "/"+placeholder {
		t.Fatalf("redirect target received %+v", seen)
	}
	h.noUse()
}

func FuzzPathInjection(f *testing.F) {
	const prefix = "/v4/spreadsheets/A"
	const exact = "/mounted/" + placeholder
	const tok = "123:fake-path-token"
	const bound, unbound = "example.com", "other.example.com"
	for _, raw := range []string{
		prefix + "/" + placeholder, prefix + ":" + placeholder, prefix + "B/" + placeholder,
		prefix + "/../" + placeholder, prefix + "/x%2Fy/" + placeholder, prefix + "/x%3Ay/" + placeholder,
		prefix + "/%70" + placeholder[1:], "/outside/%70" + placeholder[1:], prefix + "/" + placeholder + "/" + placeholder,
		exact, exact + "/values", prefix + "/%2e/" + placeholder,
		prefix + "/../B/" + placeholder, prefix + "/%2e%2e/B/" + placeholder, prefix + "/%2E/" + placeholder,
		prefix + "%2f../B/" + placeholder, prefix + "/..%2FB/" + placeholder,
		prefix + "/.%2E/B/" + placeholder, prefix + "/%2e.%2fB/" + placeholder, prefix + "/%2E%2e%2FB/" + placeholder,
	} {
		f.Add(raw, true)
		f.Add(raw, false)
	}
	roots := x509.NewCertPool()
	routes := make(map[string]string)
	for _, host := range []string{bound, unbound} {
		up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host {
				http.Error(w, "wrong host", http.StatusMisdirectedRequest)
				return
			}
			w.Header().Set("X-Upstream-Host", host)
			_, _ = io.WriteString(w, r.URL.RequestURI())
		}))
		f.Cleanup(up.Close)
		roots.AddCert(up.Certificate())
		routes[host+":443"] = up.Listener.Addr().String()
	}
	b := pathBinding(tok)
	b.Hosts = []string{bound}
	b.PathPrefixes = []string{prefix, exact}
	h := startProxy(f, Config{Bindings: []Binding{b}}, roots, routes)
	roots = roots.Clone()
	roots.AppendCertsFromPEM(h.proxy.CACertPEM())
	client := h.client(false, roots)
	f.Fuzz(func(t *testing.T, raw string, onBound bool) {
		u, err := url.ParseRequestURI(raw)
		if err != nil || !strings.HasPrefix(raw, "/") || strings.Contains(u.Path, tok) {
			return
		}
		path := u.EscapedPath()
		host := unbound
		if onBound {
			host = bound
		}
		target := path + "?q=" + placeholder
		resp, err := client.Get("https://" + host + target)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		var use Use
		if onBound {
			select {
			case use = <-h.uses:
			case <-time.After(5 * time.Second):
				t.Fatal("missing Use")
			}
			if use.Path != path || strings.Contains(use.Path, tok) {
				t.Fatalf("recorded path %q for %q", use.Path, path)
			}
		}
		allowed := func(path string) bool {
			segments := strings.Split(path, "/")
			lower := strings.ToLower(path)
			if strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") || slices.Contains(segments, ".") || slices.Contains(segments, "..") {
				return false
			}
			for _, p := range b.PathPrefixes {
				if path == p || strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p+":") {
					return true
				}
			}
			return false
		}
		if onBound && strings.Count(u.Path, placeholder) != strings.Count(path, placeholder) {
			if use.Injected || use.Err != "encoded path placeholder" || resp.Header.Get("X-Upstream-Host") != "" {
				t.Fatalf("encoded placeholder forwarded for %q", raw)
			}
			return
		}
		want := target
		if onBound && allowed(path) {
			forwarded := strings.ReplaceAll(path, placeholder, tok)
			if !allowed(forwarded) {
				if use.Injected || use.Err != "injected path outside binding" || resp.Header.Get("X-Upstream-Host") != "" {
					t.Fatalf("out-of-scope substitution forwarded for %q", raw)
				}
				return
			}
			want = forwarded + "?q=" + placeholder
		}
		forwarded, _, _ := strings.Cut(string(body), "?")
		if strings.Contains(forwarded, tok) && (resp.Header.Get("X-Upstream-Host") != bound || !allowed(forwarded)) {
			t.Fatalf("token reached host %q path %q", resp.Header.Get("X-Upstream-Host"), forwarded)
		}
		if gotHost := resp.Header.Get("X-Upstream-Host"); gotHost != host || string(body) != want || use.Injected != strings.Contains(want, tok) {
			t.Fatalf("upstream host %q target %q, want %q %q, injected %t", gotHost, body, host, want, use.Injected)
		}
	})
}

func TestSharedPathBindings(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	first := pathBinding("other-placeholder")
	second := pathBinding("example/second")
	second.ID, second.Placeholder = "second", "other-placeholder"
	scoped := headerBinding(staticToken(nil))
	scoped.ID, scoped.PathPrefixes = "sheet", []string{"/spreadsheets/" + placeholder}
	h := startProxy(t, Config{Bindings: []Binding{first, second, scoped}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	client := h.client(false, h.caPool)
	path := "/" + second.Placeholder + "/" + first.Placeholder
	resp, err := client.Get("https://" + boundHost + path)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	u := h.nextUse()
	if seen := up.seen(); len(seen) != 1 || seen[0].path != "/example/second/other-placeholder" || u.BindingID != "path,second" || !u.Injected || u.Path != path {
		t.Fatalf("upstream %+v Use %+v", seen, u)
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+boundHost+"/spreadsheets/"+placeholder, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+scoped.Placeholder)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	u = h.nextUse()
	if resp.StatusCode != http.StatusForbidden || u.Err != "injected path outside binding" || u.Injected || len(up.seen()) != 1 {
		t.Fatalf("scope after substitution: status %d Use %+v", resp.StatusCode, u)
	}
}

func TestCheckRefusal(t *testing.T) {
	const grant = "command-placeholder"
	headers := http.Header{"X-Policy": {"first", "second"}}
	for _, tc := range []struct {
		name         string
		err          error
		status       int
		reason, body string
	}{
		{"custom", &Refusal{Status: 429, Header: headers, Reason: "quota", Body: []byte("slow\x00down")}, 429, "quota", "slow\x00down"},
		{"minimum", &Refusal{Status: 400}, 400, "", ""},
		{"maximum", &Refusal{Status: 499}, 499, "", ""},
		{"zero", &Refusal{Body: []byte("declined")}, 403, "", "declined"},
		{"below", &Refusal{Status: 399, Reason: "policy"}, 403, "policy", ""},
		{"above", &Refusal{Status: 500, Reason: "policy"}, 403, "policy", ""},
		{"generic", errors.New("private details"), 403, "refused", "Forbidden\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls, checks atomic.Int32
			first := headerBinding(staticToken(&calls))
			first.Check = func(_ *http.Request, presented string) error {
				checks.Add(1)
				if presented != first.Placeholder {
					t.Errorf("first Check got %q", presented)
				}
				return nil
			}
			second := Binding{ID: "key", Hosts: first.Hosts, Placeholder: "key-placeholder", Injects: []Injection{keyInjection}, Token: staticToken(&calls)}
			second.Check = func(_ *http.Request, presented string) error {
				checks.Add(1)
				if presented != grant {
					t.Errorf("second Check got %q", presented)
				}
				return tc.err
			}
			ca := newTestCA(t)
			up := startUpstream(t, ca, boundHost, nil)
			h := startProxy(t, Config{Bindings: []Binding{first, second}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
			revoke, err := h.proxy.Grant(second.ID, grant)
			if err != nil {
				t.Fatal(err)
			}
			defer revoke()
			req, _ := http.NewRequest(http.MethodPost, "https://"+boundHost+"/path?private=value", nil)
			req.Header.Set("Authorization", bearerInjection.value(placeholder))
			req.Header.Set("X-Api-Key", grant)
			resp, err := h.client(true, h.caPool).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != tc.status || string(body) != tc.body {
				t.Fatalf("HTTP %d, body %q, read error %v", resp.StatusCode, body, err)
			}
			if tc.name == "custom" && !slices.Equal(resp.Header.Values("X-Policy"), headers["X-Policy"]) {
				t.Errorf("refusal headers %v", resp.Header)
			}
			if u := h.nextUse(); u.Status != tc.status || u.Err != tc.reason || u.Injected || !u.Granted || u.BindingID != "github,key" || u.Path != "/path" || u.Method != http.MethodPost || u.Host != boundHost || u.At.IsZero() {
				t.Errorf("Use %+v", u)
			}
			if checks.Load() != 2 || calls.Load() != 0 || h.dials.Load() != 0 || len(up.seen()) != 0 {
				t.Errorf("Check calls %d, Token calls %d, upstream dials %d, upstream requests %d", checks.Load(), calls.Load(), h.dials.Load(), len(up.seen()))
			}
		})
	}
}

func TestCheckOverlappingForms(t *testing.T) {
	const grant = "command-placeholder"
	var firstChecks, secondChecks, calls atomic.Int32
	first := headerBinding(staticToken(&calls))
	first.Injects = append(first.Injects, keyInjection)
	first.Check = func(_ *http.Request, presented string) error {
		firstChecks.Add(1)
		if presented != first.Placeholder {
			t.Errorf("first Check got %q", presented)
		}
		return &Refusal{Status: 409}
	}
	second := headerBinding(staticToken(&calls))
	second.ID, second.Placeholder = "second", "second-placeholder"
	second.Check = func(_ *http.Request, presented string) error {
		secondChecks.Add(1)
		if presented != second.Placeholder {
			t.Errorf("second Check got %q", presented)
		}
		return nil
	}
	h := startProxy(t, Config{Bindings: []Binding{first, second}}, nil, map[string]string{})
	revoke, err := h.proxy.Grant(first.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/", nil)
	req.Header["Authorization"] = []string{bearerInjection.value(first.Placeholder), bearerInjection.value(second.Placeholder)}
	req.Header.Set("X-Api-Key", grant)
	resp, err := h.client(false, h.caPool).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if u := h.nextUse(); resp.StatusCode != 409 || !u.Granted || u.Injected || calls.Load() != 0 || firstChecks.Load() != 1 || secondChecks.Load() != 1 {
		t.Fatalf("HTTP %d, Use %+v, Check calls %d/%d, Token calls %d", resp.StatusCode, u, firstChecks.Load(), secondChecks.Load(), calls.Load())
	}
}

func TestCheckAfterTargetValidation(t *testing.T) {
	var checks atomic.Int32
	b := headerBinding(staticToken(nil))
	b.Check = func(*http.Request, string) error {
		checks.Add(1)
		return errors.New("unexpected Check")
	}
	h := startProxy(t, Config{Bindings: []Binding{b}}, nil, map[string]string{})
	for _, tc := range []struct {
		method, target, host string
		want                 int
	}{
		{http.MethodConnect, boundHost + ":443", boundHost, 405},
		{http.MethodGet, "mailto:user", boundHost, 400},
		{http.MethodGet, "/", otherHost, 421},
	} {
		conn, err := h.tlsTunnel(boundHost+":443", boundHost, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", tc.method, tc.target, tc.host, placeholder)
		resp, _ := rawExchange(t, conn, req)
		conn.Close()
		if resp.StatusCode != tc.want || checks.Load() != 0 {
			t.Errorf("%s %s: HTTP %d, Check calls %d", tc.method, tc.target, resp.StatusCode, checks.Load())
		}
	}
}

func TestCheckRestoresBody(t *testing.T) {
	const payload = "before\x00after\n"
	ca := newTestCA(t)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, "%d %v %s", r.ContentLength, r.TransferEncoding, body)
	}))
	up.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, boundHost)}}
	up.StartTLS()
	t.Cleanup(up.Close)
	var checks, calls atomic.Int32
	b := headerBinding(staticToken(&calls))
	b.Check = func(r *http.Request, presented string) error {
		checks.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		if string(body) != payload || presented != placeholder {
			t.Errorf("Check received body %q, placeholder %q", body, presented)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.Listener.Addr().String()})
	client := h.client(false, h.caPool)
	for _, length := range []int64{int64(len(payload)), -1} {
		req, _ := http.NewRequest(http.MethodPost, "https://"+boundHost+"/", strings.NewReader(payload))
		req.ContentLength = length
		req.Header.Set("Authorization", bearerInjection.value(placeholder))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		var encoding []string
		if length == -1 {
			encoding = []string{"chunked"}
		}
		want := fmt.Sprintf("%d %v %s", length, encoding, payload)
		if err != nil || string(body) != want {
			t.Fatalf("upstream framing and body %q, want %q, read error %v", body, want, err)
		}
		if u := h.nextUse(); !u.Injected || u.Granted || u.Status != http.StatusOK || u.Err != "" {
			t.Fatalf("Use %+v", u)
		}
	}
	if checks.Load() != 2 || calls.Load() != 2 {
		t.Errorf("Check calls %d, Token calls %d", checks.Load(), calls.Load())
	}
}

func TestGrantLifetime(t *testing.T) {
	const grant = "command-placeholder"
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	})
	var calls atomic.Int32
	b := headerBinding(staticToken(&calls))
	other := basicBinding(staticToken(nil))
	other.Placeholder = "other-placeholder"
	h := startProxy(t, Config{Bindings: []Binding{b, other}, ScanResponses: true}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	client := h.client(true, h.caPool)
	revoke, err := h.proxy.Grant(b.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, value string }{
		{"unknown", "unused"}, {other.ID, grant}, {b.ID, other.Placeholder}, {b.ID, ""}, {b.ID, placeholder}, {b.ID, grant},
	} {
		if _, err := h.proxy.Grant(tc.id, tc.value); err == nil {
			t.Errorf("accepted invalid grant %q on %q", tc.value, tc.id)
		}
	}
	check := func(method, value, want string, granted bool) {
		t.Helper()
		before := calls.Load()
		req, _ := http.NewRequest(method, "https://"+boundHost+"/path", nil)
		req.Header.Set("Authorization", "Bearer "+value)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		wantBody := "Bearer " + want
		if want == realToken {
			wantBody = "Bearer " + b.Placeholder
		}
		if err != nil || string(body) != wantBody {
			t.Fatalf("response body %q, read error %v, want %q", body, err, wantBody)
		}
		use := h.nextUse()
		if resp.StatusCode != 200 || use.Status != 200 || use.Err != "" || use.Granted != granted || use.Injected != (want == realToken) {
			t.Fatalf("%s with %q: HTTP %d, Use %+v", method, value, resp.StatusCode, use)
		}
		seen := up.seen()
		if len(seen) == 0 || seen[len(seen)-1].header.Get("Authorization") != "Bearer "+want {
			t.Fatalf("upstream credential mismatch for %s with %q", method, value)
		}
		wantCalls := int32(0)
		if want == realToken {
			wantCalls = 1
		}
		if calls.Load()-before != wantCalls {
			t.Fatalf("Token calls = %d, want %d", calls.Load()-before, wantCalls)
		}
	}

	check("GET", placeholder, realToken, false)
	check("GET", grant, realToken, true)
	check("GET", other.Placeholder, other.Placeholder, false)
	check("POST", grant, realToken, true)
	impl := h.proxy.impl
	impl.grantsMu.Lock()
	active := len(impl.bindings[b.ID].grants[grant])
	impl.grantsMu.Unlock()
	if active != 0 {
		t.Fatalf("live grant retained %d completed requests", active)
	}
	revoke()
	check("POST", grant, grant, false)
	revokeAgain, err := h.proxy.Grant(b.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeAgain()
	revoke()
	check("POST", grant, realToken, true)
	check("POST", placeholder, realToken, false)
}

func TestGrantDuringRequest(t *testing.T) {
	const grant = "shared-grant"
	ca := newTestCA(t)
	var tokens atomic.Int32
	first := headerBinding(staticToken(&tokens))
	second := basicBinding(staticToken(nil))
	up := startUpstream(t, ca, boundHost, nil)
	other := startUpstream(t, ca, basicHost, nil)
	var checks atomic.Int32
	entered, resume := make(chan struct{}), make(chan struct{})
	first.Check = func(r *http.Request, presented string) error {
		checks.Add(1)
		if presented != grant {
			t.Errorf("Check received %q, want %q", presented, grant)
		}
		close(entered)
		select {
		case <-resume:
		case <-r.Context().Done():
		}
		return nil
	}
	h := startProxy(t, Config{Bindings: []Binding{first, second}}, ca.pool, map[string]string{
		boundHost + ":443": up.srv.Listener.Addr().String(), basicHost + ":443": other.srv.Listener.Addr().String(),
	})
	revoke, err := h.proxy.Grant(first.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	client := h.client(true, h.caPool)
	request := func(host string, form Injection, wantStatus int) error {
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		req.Header.Set(form.headerName(), form.value(grant))
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != wantStatus {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	}
	if err := request(basicHost, basicInjection, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); u.Granted || u.Injected {
		t.Fatalf("grant matched on another binding: %+v", u)
	}
	done := make(chan error, 1)
	go func() { done <- request(boundHost, bearerInjection, http.StatusBadGateway) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("request returned before Check: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Check did not start")
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			revoke()
		}()
	}
	wg.Wait()
	revokeSecond, err := h.proxy.Grant(second.ID, grant)
	close(resume)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeSecond()
	revoke()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); !u.Granted || u.Injected || u.Err != "grant revoked" || checks.Load() != 1 || tokens.Load() != 0 {
		t.Fatalf("in-flight request: %+v, Check calls %d", u, checks.Load())
	}
	if err := request(boundHost, bearerInjection, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); u.Granted || u.Injected || checks.Load() != 1 {
		t.Fatalf("revoked request: %+v, Check calls %d", u, checks.Load())
	}
	if err := request(basicHost, basicInjection, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); !u.Granted || !u.Injected {
		t.Fatalf("reassigned grant: %+v", u)
	}
}

func TestRevokeStopsUpload(t *testing.T) {
	const placeholderGrant = "upload-grant"
	for _, clientH2 := range []bool{false, true} {
		for _, upstreamH2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("clientH2=%t/upstreamH2=%t", clientH2, upstreamH2), func(t *testing.T) {
				ca := newTestCA(t)
				headers := make(chan string, 1)
				read := make(chan string, 1)
				up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					headers <- r.Header.Get("Authorization")
					body, _ := io.ReadAll(r.Body)
					read <- string(body)
				}))
				up.EnableHTTP2 = upstreamH2
				up.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, boundHost)}}
				up.StartTLS()
				t.Cleanup(up.Close)

				tokenContext := make(chan context.Context, 1)
				b := headerBinding(func(ctx context.Context) (string, error) {
					tokenContext <- ctx
					return realToken, nil
				})
				b.Check = func(r *http.Request, presented string) error {
					if r.Method != http.MethodGet && presented != placeholderGrant {
						return errors.New("write requires grant")
					}
					return nil
				}
				h := startProxy(t, Config{Bindings: []Binding{b}}, ca.pool, map[string]string{boundHost + ":443": up.Listener.Addr().String()})
				revoke, err := h.proxy.Grant(b.ID, placeholderGrant)
				if err != nil {
					t.Fatal(err)
				}
				client := h.client(clientH2, h.caPool)
				pr, pw := io.Pipe()
				defer pw.Close()
				req, _ := http.NewRequest(http.MethodPut, "https://"+boundHost+"/upload", pr)
				req.Header.Set("Authorization", bearerInjection.value(placeholderGrant))
				done := make(chan struct{})
				go func() {
					defer close(done)
					resp, err := client.Do(req)
					if err == nil {
						resp.Body.Close()
					}
				}()
				select {
				case auth := <-headers:
					if auth != bearerInjection.value(realToken) {
						t.Fatal("upstream did not receive the injected header")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("upstream did not receive the headers")
				}
				ctx := <-tokenContext
				revoke()
				if ctx.Err() != context.Canceled {
					t.Fatal("grant request context still live after revoke returned")
				}
				_, _ = io.WriteString(pw, "payload")
				_ = pw.Close()
				select {
				case body := <-read:
					if body != "" {
						t.Errorf("upstream received %d body bytes after revoke", len(body))
					}
				case <-time.After(5 * time.Second):
					t.Error("upstream upload did not end")
				}
				<-done
				if u := h.nextUse(); !u.Granted || !u.Injected || u.Err != "grant revoked" {
					t.Errorf("Use %+v", u)
				}
			})
		}
	}
}

func TestRevokeAffectsOnlyInjectedGrants(t *testing.T) {
	const placeholderGrant = "extra"
	for _, tc := range []struct {
		name        string
		headers     []string
		wantGranted bool
	}{
		{"own placeholder", []string{bearerInjection.value(placeholder)}, false},
		{"other binding claimed header", []string{bearerInjection.value(placeholder), bearerInjection.value(placeholderGrant)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			upstreamStarted := make(chan struct{})
			ca := newTestCA(t)
			up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
				close(upstreamStarted)
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})
			entered := make(chan context.Context, 1)
			b := headerBinding(func(ctx context.Context) (string, error) {
				entered <- ctx
				return realToken, nil
			})
			other := headerBinding(staticToken(nil))
			other.ID, other.Placeholder = "other", "other-placeholder"
			h := startProxy(t, Config{Bindings: []Binding{b, other}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
			grantID := b.ID
			if tc.wantGranted {
				grantID = other.ID
			}
			revoke, err := h.proxy.Grant(grantID, placeholderGrant)
			if err != nil {
				t.Fatal(err)
			}
			client := h.client(true, h.caPool)
			req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/", nil)
			req.Header["Authorization"] = tc.headers
			done := make(chan error, 1)
			go func() {
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						err = fmt.Errorf("HTTP %d", resp.StatusCode)
					}
				}
				done <- err
			}()
			select {
			case <-upstreamStarted:
				ctx := <-entered
				revoke()
				if err := ctx.Err(); err != nil {
					t.Errorf("primary credential context: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("upstream request did not start")
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if u := h.nextUse(); u.Granted != tc.wantGranted || !u.Injected || u.Err != "" || u.BindingID != b.ID {
				t.Fatalf("Use %+v", u)
			}
		})
	}
}

func TestRevokeDuringResponse(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ready")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	b := headerBinding(staticToken(nil))
	second := Binding{ID: "key", Hosts: b.Hosts, Placeholder: "key-placeholder", Injects: []Injection{keyInjection}, Token: staticToken(nil)}
	h := startProxy(t, Config{Bindings: []Binding{b, second}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	client := h.client(true, h.caPool)
	for _, revokeID := range []string{b.ID, second.ID} {
		t.Run(revokeID, func(t *testing.T) {
			revokers := make(map[string]func())
			req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/", nil)
			for _, binding := range []Binding{b, second} {
				ph := binding.ID + "-grant"
				revoke, err := h.proxy.Grant(binding.ID, ph)
				if err != nil {
					t.Fatal(err)
				}
				defer revoke()
				revokers[binding.ID] = revoke
				form := binding.Injects[0]
				req.Header.Set(form.headerName(), form.value(ph))
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			buf := make([]byte, len("ready"))
			if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "ready" {
				t.Fatalf("response prefix %q, error %v", buf, err)
			}
			revokers[revokeID]()
			if u := h.nextUse(); !u.Granted || !u.Injected || u.Status != http.StatusOK || u.Err != "grant revoked" || u.BindingID != "github,key" {
				t.Fatalf("Use %+v", u)
			}
		})
	}
}

func TestConcurrentGrantLifetimes(t *testing.T) {
	b := headerBinding(staticToken(nil))
	p, err := New(Config{Bindings: []Binding{b}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ph := fmt.Sprintf("grant-%d", i)
			for range 32 {
				revoke, err := p.Grant(b.ID, ph)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := p.Grant(b.ID, ph); err == nil {
					t.Error("duplicate live grant accepted")
				}
				revoke()
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestConnectHeaderLimit(t *testing.T) {
	ca := newTestCA(t)
	up := startUpstream(t, ca, boundHost, nil)
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, ca.pool, map[string]string{boundHost + ":443": up.srv.Listener.Addr().String()})
	line := "CONNECT " + boundHost + ":443 HTTP/1.1\r\nX-Pad: "
	for _, tc := range []struct {
		name, header string
		want         int
	}{
		{"complete at the limit", line + strings.Repeat("a", maxConnectBytes-len(line)-4) + "\r\n\r\n", http.StatusOK},
		{"complete at the limit, then tunnel bytes", line + strings.Repeat("a", maxConnectBytes-len(line)-4) + "\r\n\r\n" + strings.Repeat("b", 8192), http.StatusOK},
		{"unfinished at the limit", line + strings.Repeat("a", maxConnectBytes-len(line)), http.StatusRequestHeaderFieldsTooLarge},
	} {
		c, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, tc.header); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		status, err := bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
		if err != nil || !strings.Contains(status, fmt.Sprintf(" %d ", tc.want)) {
			t.Fatalf("%s: status line %q, err %v, want %d", tc.name, status, err, tc.want)
		}
	}

	body := strings.Repeat("b", 4*maxConnectBytes)
	req, _ := http.NewRequest(http.MethodPost, "https://"+boundHost+"/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+placeholder)
	res, err := h.client(false, h.caPool).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if seen := up.seen(); res.StatusCode != http.StatusOK || len(seen) != 1 || seen[0].body != body {
		t.Fatalf("upload larger than the CONNECT limit: status %d, upstream requests %d", res.StatusCode, len(seen))
	}
}

func TestOpaqueRequestTargetRefused(t *testing.T) {
	ca := newTestCA(t)
	var received, calls atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	up.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, boundHost)}, NextProtos: []string{"http/1.1"}}
	up.StartTLS()
	t.Cleanup(up.Close)
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(&calls))}}, ca.pool, map[string]string{boundHost + ":443": up.Listener.Addr().String()})
	for _, target := range []string{"x:https://" + otherHost + "/a", "https:https://" + otherHost + "/a", "a:http://" + otherHost + ":80/a?q=1", "mailto:a@" + otherHost} {
		c, err := h.tlsTunnel(boundHost+":443", boundHost, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := rawExchange(t, c, "GET "+target+" HTTP/1.1\r\nHost: "+boundHost+"\r\nAuthorization: Bearer "+placeholder+"\r\nConnection: close\r\n\r\n")
		_ = c.Close()
		if u := h.nextUse(); resp.StatusCode != http.StatusBadRequest || u.Injected || u.Err == "" {
			t.Errorf("target %q: status %d, use %+v, want 400 and no injection", target, resp.StatusCode, u)
		}
	}
	if received.Load() != 0 || calls.Load() != 0 {
		t.Fatalf("upstream requests %d, token calls %d, want none", received.Load(), calls.Load())
	}
}
