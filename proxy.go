package hostbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	handshakeTimeout = 30 * time.Second
	maxConnectBytes  = 64 << 10
	dialTimeout      = 30 * time.Second
	recentTokens     = 4
)

type binding struct {
	Binding
	mu     sync.Mutex
	recent []string
}

func (b *binding) remember(token string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if slices.Contains(b.recent, token) {
		return
	}
	b.recent = append([]string{token}, b.recent...)[:min(len(b.recent)+1, recentTokens)]
}

func (b *binding) scanPairs(current string) []secretPair {
	b.mu.Lock()
	tokens := slices.Clone(b.recent)
	b.mu.Unlock()
	if current != "" && !slices.Contains(tokens, current) {
		tokens = append(tokens, current)
	}
	var pairs []secretPair
	for _, t := range tokens {
		pairs = append(pairs, secretPair{[]byte(t), []byte(b.Placeholder)})
		if u := b.Inject.BasicUser; u != "" {
			enc := base64.StdEncoding.EncodeToString
			pairs = append(pairs, secretPair{[]byte(enc([]byte(u + ":" + t))), []byte(enc([]byte(u + ":" + b.Placeholder)))})
		}
	}
	return pairs
}

type proxy struct {
	cfg       Config
	hosts     map[string][]*binding
	ca        *authority
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	transport *http.Transport
	rp        *httputil.ReverseProxy
	srv       *http.Server
	tunnels   *tunnelListener

	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	conns     map[net.Conn]struct{}
}

func newProxy(cfg Config) (*Proxy, error) {
	p := &proxy{
		cfg:       cfg,
		hosts:     make(map[string][]*binding),
		listeners: make(map[net.Listener]struct{}),
		conns:     make(map[net.Conn]struct{}),
	}
	ids := make(map[string]bool)
	var hosts []string
	for _, b := range cfg.Bindings {
		switch {
		case b.ID == "" || ids[b.ID]:
			return nil, fmt.Errorf("hostbound: binding ID %q is empty or repeated", b.ID)
		case b.Placeholder == "" || b.Token == nil || len(b.Hosts) == 0:
			return nil, fmt.Errorf("hostbound: binding %q needs Hosts, Placeholder and Token", b.ID)
		}
		if err := b.Inject.validate(); err != nil {
			return nil, fmt.Errorf("hostbound: binding %q: %w", b.ID, err)
		}
		ids[b.ID] = true
		bb := &binding{Binding: b}
		for _, h := range b.Hosts {
			n, port, ok := parseAuthority(h)
			if _, err := netip.ParseAddr(h); !ok || port != "" || n != h || err == nil {
				return nil, fmt.Errorf("hostbound: binding %q: %q is not a lower-case host name", b.ID, h)
			}
			if slices.Contains(p.hosts[h], bb) {
				return nil, fmt.Errorf("hostbound: binding %q lists host %q twice", b.ID, h)
			}
			if len(p.hosts[h]) == 0 {
				hosts = append(hosts, h)
			}
			p.hosts[h] = append(p.hosts[h], bb)
		}
	}
	ca, err := newAuthority(hosts)
	if err != nil {
		return nil, fmt.Errorf("hostbound: create CA: %w", err)
	}
	p.ca = ca
	p.dial = cfg.DialContext
	if p.dial == nil {
		p.dial = guardedDialer(cfg.DenyPrefixes).DialContext
	}
	discard := log.New(io.Discard, "", 0)
	p.transport = &http.Transport{
		DialContext:         p.dial,
		TLSClientConfig:     &tls.Config{RootCAs: cfg.UpstreamRoots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: handshakeTimeout,
		IdleConnTimeout:     90 * time.Second,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      p.transport,
		FlushInterval:  -1,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.upstreamError,
		ErrorLog:       discard,
	}
	p.tunnels = &tunnelListener{ch: make(chan net.Conn), done: make(chan struct{})}
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.handle),
		ConnContext:       tunnelContext,
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          discard,
	}
	go func() { _ = p.srv.Serve(p.tunnels) }()
	return &Proxy{impl: p}, nil
}

func (p *proxy) caCertPEM() []byte { return slices.Clone(p.ca.certPEM) }

func (p *proxy) serve(ln net.Listener) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ln.Close()
	}
	p.listeners[ln] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.listeners, ln)
		p.mu.Unlock()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go p.handleConn(c)
	}
}

func (p *proxy) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	listeners := slices.Collect(maps.Keys(p.listeners))
	conns := slices.Collect(maps.Keys(p.conns))
	p.mu.Unlock()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	_ = p.srv.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	p.transport.CloseIdleConnections()
	return nil
}

func (p *proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *proxy) record(u Use) {
	if p.cfg.Record != nil {
		p.cfg.Record(u)
	}
}

type tunnelConn struct {
	net.Conn
	r    *bufio.Reader
	p    *proxy
	host string
	bs   []*binding
	once sync.Once
}

func (c *tunnelConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *tunnelConn) Close() error {
	c.once.Do(func() { c.p.untrack(c.Conn) })
	return c.Conn.Close()
}

type tunnelKey struct{}

func tunnelContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		if t, ok := tc.NetConn().(*tunnelConn); ok {
			return context.WithValue(ctx, tunnelKey{}, t)
		}
	}
	return ctx
}

type tunnelListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *tunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *tunnelListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *tunnelListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *tunnelListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func writeStatus(w io.Writer, code int) {
	if code == http.StatusOK {
		_, _ = io.WriteString(w, "HTTP/1.1 200 Connection Established\r\n\r\n")
		return
	}
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code))
}

func (p *proxy) handleConn(c net.Conn) {
	if !p.track(c) {
		_ = c.Close()
		return
	}
	head := &io.LimitedReader{R: c, N: maxConnectBytes}
	t := &tunnelConn{Conn: c, r: bufio.NewReader(head), p: p}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = t.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	req, err := http.ReadRequest(t.r)
	if err != nil {
		status := http.StatusBadRequest
		if head.N <= 0 {
			status = http.StatusRequestHeaderFieldsTooLarge
		}
		writeStatus(c, status)
		return
	}
	head.N = math.MaxInt64
	if req.Method != http.MethodConnect {
		writeStatus(c, http.StatusMethodNotAllowed)
		return
	}
	host, port, ok := parseAuthority(req.RequestURI)
	if !ok || port == "" {
		writeStatus(c, http.StatusBadRequest)
		return
	}
	bs := p.hosts[host]
	if len(bs) == 0 {
		p.splice(t, host, port)
		return
	}
	connectUse := Use{BindingID: bindingIDs(bs), Host: host, Method: http.MethodConnect, At: time.Now()}
	if port != boundPort {
		connectUse.Status, connectUse.Err = http.StatusForbidden, "port not bound"
		p.record(connectUse)
		writeStatus(c, http.StatusForbidden)
		return
	}
	writeStatus(c, http.StatusOK)
	t.host, t.bs = host, bs
	leaf := p.ca.leaves[host]
	tc := tls.Server(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if sni, port, ok := parseAuthority(hello.ServerName); !ok || port != "" || sni != host {
				return nil, errors.New("hostbound: SNI does not match CONNECT host")
			}
			return leaf, nil
		},
	})
	if err := tc.Handshake(); err != nil {
		connectUse.Err = "tls handshake failed"
		p.record(connectUse)
		return
	}
	_ = c.SetDeadline(time.Time{})
	handedOff = p.tunnels.push(tc)
}

func (p *proxy) splice(t *tunnelConn, host, port string) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	up, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		writeStatus(t, http.StatusBadGateway)
		return
	}
	if !p.track(up) {
		_ = up.Close()
		return
	}
	defer func() {
		p.untrack(up)
		_ = up.Close()
	}()
	_ = t.SetDeadline(time.Time{})
	writeStatus(t, http.StatusOK)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, t)
		closeWrite(up)
		close(done)
	}()
	_, _ = io.Copy(t, up)
	closeWrite(t.Conn)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

type exchange struct {
	bs       []*binding
	tokens   map[*binding]string
	use      Use
	recorded bool
}

func bindingIDs(bs []*binding) string {
	ids := make([]string, len(bs))
	for i, b := range bs {
		ids[i] = b.ID
	}
	return strings.Join(ids, ",")
}

func (x *exchange) scanPairs() []secretPair {
	var pairs []secretPair
	for _, b := range x.bs {
		pairs = append(pairs, b.scanPairs(x.tokens[b])...)
	}
	return pairs
}

func (p *proxy) finish(x *exchange) {
	if !x.recorded {
		x.recorded = true
		p.record(x.use)
	}
}

type exchangeKey struct{}

func (x *exchange) fail(w http.ResponseWriter, code int, msg string) {
	x.use.Status, x.use.Err = code, msg
	http.Error(w, http.StatusText(code), code)
}

func authorityMatches(host string, r *http.Request) bool {
	if !sameAuthority(host, r.Host) || (r.URL.Host != "" && !sameAuthority(host, r.URL.Host)) {
		return false
	}
	for _, v := range r.Header.Values("Host") {
		if !sameAuthority(host, v) {
			return false
		}
	}
	return true
}

func (p *proxy) handle(w http.ResponseWriter, r *http.Request) {
	t := r.Context().Value(tunnelKey{}).(*tunnelConn)
	x := &exchange{bs: t.bs, tokens: make(map[*binding]string), use: Use{BindingID: bindingIDs(t.bs), Host: t.host, Method: r.Method, Path: r.URL.Path, At: time.Now()}}
	defer p.finish(x)
	switch {
	case r.Method == http.MethodConnect:
		x.fail(w, http.StatusMethodNotAllowed, "CONNECT inside a tunnel")
		return
	case r.URL.Opaque != "":
		x.fail(w, http.StatusBadRequest, "request target has no path")
		return
	case !authorityMatches(t.host, r):
		x.fail(w, http.StatusMisdirectedRequest, "request authority does not match CONNECT host")
		return
	}
	var injected []*binding
	headers := make(map[string]bool)
	for _, b := range t.bs {
		if headers[b.Inject.headerName()] || !b.Inject.carries(r.Header, b.Placeholder) {
			continue
		}
		headers[b.Inject.headerName()] = true
		injected = append(injected, b)
		token, err := b.Token(r.Context())
		if err != nil || token == "" {
			x.use.BindingID = bindingIDs(injected)
			x.fail(w, http.StatusBadGateway, "token unavailable")
			return
		}
		if p.cfg.ScanResponses {
			b.remember(token)
		}
		x.tokens[b] = token
	}
	if len(injected) > 0 {
		x.use.BindingID = bindingIDs(injected)
	}
	if p.cfg.ScanResponses {
		w = interimScanner{ResponseWriter: w, x: x}
	}
	p.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), exchangeKey{}, x)))
}

type interimScanner struct {
	http.ResponseWriter
	x *exchange
}

func (w interimScanner) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		newReplacer(w.x.scanPairs()).replaceHeader(w.Header())
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w interimScanner) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (p *proxy) rewrite(pr *httputil.ProxyRequest) {
	x := pr.In.Context().Value(exchangeKey{}).(*exchange)
	pr.Out.URL.Scheme = "https"
	pr.Out.URL.Host = x.use.Host
	pr.Out.URL.User = nil
	pr.Out.Host = x.use.Host
	pr.Out.Header.Del("Host")
	for _, b := range x.bs {
		if token := x.tokens[b]; token != "" {
			b.Inject.apply(pr.Out.Header, token)
			x.use.Injected = true
		}
	}
	if p.cfg.ScanResponses {
		pr.Out.Header.Set("Accept-Encoding", "identity")
	}
}

func (p *proxy) modifyResponse(resp *http.Response) error {
	x := resp.Request.Context().Value(exchangeKey{}).(*exchange)
	if p.cfg.ScanResponses {
		if pairs := x.scanPairs(); len(pairs) > 0 {
			if err := scanResponse(resp, newReplacer(pairs)); err != nil {
				return err
			}
		}
	}
	x.use.Status = resp.StatusCode
	if resp.StatusCode == http.StatusSwitchingProtocols {
		p.finish(x)
	}
	return nil
}

func (p *proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	x := r.Context().Value(exchangeKey{}).(*exchange)
	msg, sent := errorCategory(err)
	x.use.Injected = x.use.Injected && sent
	x.fail(w, http.StatusBadGateway, msg)
}

func errorCategory(err error) (msg string, requestSent bool) {
	var cve *tls.CertificateVerificationError
	var op *net.OpError
	switch {
	case errors.Is(err, errDenied):
		return "dial denied by address guard", false
	case errors.Is(err, errUnscannable):
		return "response encoding cannot be scanned", true
	case errors.Is(err, context.Canceled):
		return "client canceled", true
	case errors.Is(err, context.DeadlineExceeded):
		return "upstream timeout", true
	case errors.As(err, &cve):
		return "upstream certificate rejected", false
	case errors.As(err, &op) && op.Op == "dial":
		return "upstream dial failed", false
	default:
		return "upstream request failed", true
	}
}
