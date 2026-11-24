// Package hostbound provides an HTTPS forward proxy for clients that hold a
// placeholder for a credential. A binding names the hosts and injection forms
// where the proxy may substitute the credential.
//
// For a bound host, the proxy accepts CONNECT on port 443 and terminates TLS
// with a certificate issued by its in-memory CA. The CONNECT target, TLS SNI
// and HTTP request authority must agree. Injection requires a matching header
// or path form and an allowed path. The proxy verifies the upstream TLS certificate.
// It tunnels connections to unbound hosts without decrypting them.
//
// With Config.ScanResponses enabled, the proxy replaces reflected credentials
// in response headers, trailers and bodies with their placeholders. It scans
// for each binding's current token and up to four recently used tokens.
// Bytes after a protocol upgrade and credentials re-encoded by the upstream
// can pass through unchanged.
//
// The default dialer checks each resolved address before connecting. It denies
// loopback, private, link-local, multicast and other special-purpose ranges,
// as well as Config.DenyPrefixes. A custom DialContext replaces this check.
//
// The proxy cannot inject credentials for non-HTTP protocols or for signing
// schemes in which the client uses a key without sending it.
package hostbound
