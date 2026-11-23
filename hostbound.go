package hostbound

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
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
	// Injects lists the request header forms that can carry a placeholder. The first
	// form, in order, that carries Placeholder or a granted placeholder decides where
	// the token goes. At least one form is required, and no form may repeat.
	Injects []Injection
	// Check, when set, runs for each request that carries one of the binding's
	// placeholders, before Token. presented is the placeholder the request carried:
	// Placeholder or a value passed to Grant. A non-nil error refuses the request. A
	// *Refusal sets the response; any other error gives 403 Forbidden. Check may read
	// r.Body only if it restores it.
	Check func(r *http.Request, presented string) error
	// Token returns the current real credential. It is called once per request
	// that carries a placeholder in a declared form and passes Check.
	Token func(ctx context.Context) (string, error)
}

// Refusal is an error that a Check returns to choose the response to a refused
// request.
type Refusal struct {
	// Status is the HTTP status, 400 to 499. Zero means 403.
	Status int
	// Header is added to the response.
	Header http.Header
	// Body is the response body.
	Body []byte
	// Reason is recorded in Use.Err.
	Reason string
}

func (e *Refusal) Error() string { return e.Reason }

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
	// Granted reports whether the request carried a placeholder added by Grant.
	Granted bool
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

// Grant makes the binding accept placeholder in addition to its Placeholder until
// revoke is called. placeholder must differ from every binding's Placeholder and
// from every placeholder granted and not yet revoked. revoke can be called more
// than once.
func (p *Proxy) Grant(bindingID, placeholder string) (revoke func(), err error) {
	return p.impl.grant(bindingID, placeholder)
}

// Close stops Serve and closes open connections.
func (p *Proxy) Close() error { return p.impl.close() }
