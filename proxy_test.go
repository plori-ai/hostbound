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
		u.reqs = append(u.reqs, seenRequest{proto: r.ProtoMajor, host: r.Host, header: r.Header.Clone(), query: r.URL.RawQuery, body: string(body)})
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
	t      *testing.T
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

func startProxy(t *testing.T, cfg Config, roots *x509.CertPool, routes map[string]string) *harness {
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
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nBroken header "+r.Header.Get("Authorization")+"\r\n\r\n")
			}()
		}
	}()
	h := startProxy(t, Config{Bindings: []Binding{headerBinding(staticToken(nil))}}, ca.pool, map[string]string{boundHost + ":443": ln.Addr().String()})
	req, _ := http.NewRequest(http.MethodGet, "https://"+boundHost+"/x", nil)
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := h.client(false, h.caPool).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), realToken) {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if u := h.nextUse(); u.Err != "upstream request failed" {
		t.Fatalf("Use %+v", u)
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
	first := headerBinding(staticToken(nil))
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
			return nil
		case <-r.Context().Done():
			return r.Context().Err()
		}
	}
	h := startProxy(t, Config{Bindings: []Binding{first, second}}, ca.pool, map[string]string{
		boundHost + ":443": up.srv.Listener.Addr().String(), basicHost + ":443": other.srv.Listener.Addr().String(),
	})
	revoke, err := h.proxy.Grant(first.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	client := h.client(true, h.caPool)
	request := func(host string, form Injection) error {
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		req.Header.Set(form.headerName(), form.value(grant))
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	}
	if err := request(basicHost, basicInjection); err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); u.Granted || u.Injected {
		t.Fatalf("grant matched on another binding: %+v", u)
	}
	done := make(chan error, 1)
	go func() { done <- request(boundHost, bearerInjection) }()
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
	if u := h.nextUse(); !u.Granted || !u.Injected || checks.Load() != 1 {
		t.Fatalf("in-flight request: %+v, Check calls %d", u, checks.Load())
	}
	if err := request(boundHost, bearerInjection); err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); u.Granted || u.Injected || checks.Load() != 1 {
		t.Fatalf("revoked request: %+v, Check calls %d", u, checks.Load())
	}
	if err := request(basicHost, basicInjection); err != nil {
		t.Fatal(err)
	}
	if u := h.nextUse(); !u.Granted || !u.Injected {
		t.Fatalf("reassigned grant: %+v", u)
	}
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
