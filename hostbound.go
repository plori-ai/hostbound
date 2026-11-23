package hostbound

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"time"
)

// Injection is where a binding's token goes in a request to a bound host.
// Exactly one form is set.
type Injection struct {
	// Header names the request header used for substitution.
	Header string
	// Prefix precedes both the placeholder and the substituted token.
	Prefix string
	// BasicUser: the Authorization header must be Basic with this user name and the
	// placeholder as password; the proxy sends the same user name with the token.
	BasicUser string
}

// Binding ties one credential to the hosts it may be sent to; bindings may share a host.
type Binding struct {
	// ID identifies this binding and must be unique within a Config.
	ID string
	// Hosts are exact, lower-case host names. Only port 443 is bound.
	Hosts []string
	// Placeholder is the nonempty value presented by the client.
	Placeholder string
	// Inject specifies the request header and authentication format.
	Inject Injection
	// Token returns the current real credential. It is called once per request
	// that carries the placeholder in the declared location.
	Token func(ctx context.Context) (string, error)
}

// Use is recorded once for every request to a bound host.
type Use struct {
	// BindingID lists the injected bindings, comma-separated; with none injected, every binding of Host.
	BindingID string
	// Host is the bound CONNECT host.
	Host string
	// Method is the HTTP method.
	Method string
	// Path is the URL path without the query string.
	Path string
	// Injected reports whether the proxy sent a credential upstream.
	Injected bool
	// Status is the HTTP status, or zero if the TLS handshake failed.
	Status int
	// Err is an error category, empty on success.
	Err string
	// At is the time the proxy began handling the request.
	At time.Time
}

// Config configures a Proxy. Bindings are fixed for the life of the Proxy.
type Config struct {
	// Bindings declare credentials and the hosts that may receive them.
	Bindings []Binding
	// UpstreamRoots verifies upstream certificates; nil uses the system roots.
	UpstreamRoots *x509.CertPool
	// DenyPrefixes adds destination ranges to the default dialer's deny list.
	DenyPrefixes []netip.Prefix
	// DialContext replaces the guarded dialer. Tests use it to map host names to
	// local servers; production leaves it nil.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// ScanResponses replaces any real token found in a bound host's response
	// headers or body with the placeholder before the client sees it.
	ScanResponses bool
	// Record receives one Use per request to a bound host. It must not block.
	Record func(Use)
}

// Proxy is the running proxy.
type Proxy struct{ impl *proxy }

// New creates a Proxy with a fresh in-memory CA and leaf certificates for every
// bound host.
func New(cfg Config) (*Proxy, error) { return newProxy(cfg) }

// CACertPEM returns the CA certificate clients must trust in addition to the
// system roots.
func (p *Proxy) CACertPEM() []byte { return p.impl.caCertPEM() }

// Serve accepts CONNECT requests on ln until Close.
func (p *Proxy) Serve(ln net.Listener) error { return p.impl.serve(ln) }

// Close stops Serve and closes open connections.
func (p *Proxy) Close() error { return p.impl.close() }
