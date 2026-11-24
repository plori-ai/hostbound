# hostbound

hostbound is a Go library that provides an HTTPS forward proxy for programs that need to use a credential they never receive.

## Why

An AI agent can run commands that use a user's API key.
A key in a program's environment can end up in text that the program sends to the LLM provider.
With hostbound, the program receives a placeholder, so that text can contain only the placeholder for that key.
Keeping the key in the proxy application reduces the places it can leak from.
[Plori](https://plori.ai) built hostbound for its agent sandboxes.

## How it works

1. The program puts a placeholder in a request header or path that a binding declares.
2. The HTTPS client opens a tunnel with `CONNECT` to the proxy.
3. For a bound host on port 443, the proxy terminates client TLS using a certificate signed by a CA that `New` creates in memory.
4. If the binding has a `Check` function, the proxy calls it. `Check` can refuse the request before the proxy gets the credential.
5. The proxy replaces the placeholder in the binding's first matching injection form with the credential.
6. The proxy sends the request over a separate TLS connection and verifies the upstream certificate.
7. For hosts without a binding, the proxy passes the tunnel's bytes through without decrypting them.
8. With `ScanResponses` enabled, the proxy replaces reflected credentials in bound hosts' HTTP responses with the binding's placeholder before sending the responses to the client.

## Quick start

Use Go 1.24 or newer and `curl`. The library uses only the Go standard library.

1. Open a shell in the repository root.
2. Run the example with a made-up bearer token.

   ```sh
   DEMO_TOKEN=demo-credential go run ./examples/run -bind DEMO_TOKEN=httpbin.org -- \
     sh -c 'curl --silent --show-error --fail --max-time 20 -H "Authorization: Bearer $DEMO_TOKEN" https://httpbin.org/headers'
   ```

3. Check the echoed `Authorization` header for the placeholder.

   ```json
   {
     "headers": {
       "Accept": "*/*",
       "Accept-Encoding": "identity",
       "Authorization": "Bearer hostbound-DEMO_TOKEN-<32 hex characters>",
       "Host": "httpbin.org",
       "User-Agent": "curl/8.5.0"
     }
   }
   ```

The output above replaces the random suffix with `<32 hex characters>`.
The child shell holds only the placeholder in `DEMO_TOKEN`.
The proxy sent `Bearer demo-credential` to httpbin.org.
httpbin.org echoed that header, and the proxy replaced the credential with the placeholder in the response.

## Use as a library

This example configures a Bearer binding for an API client and a Basic-auth binding for git.
`Run` starts the proxy and runs `git ls-remote` against an HTTPS repository on `github.com`.
Pass an existing empty directory and the system root certificates in PEM format.
With an empty `rootsPEM`, the bundle holds only the proxy CA, and a client that uses it cannot verify hosts without a binding.
The caller removes the CA files after use.

```go
package example

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"

	"github.com/plori-ai/hostbound"
)

func Run(dir string, rootsPEM []byte, apiToken, gitToken, repo string) error {
	bindings := []hostbound.Binding{
		{ID: "API_TOKEN", Hosts: []string{"api.example.com"}, Placeholder: "api-placeholder",
			Injects: []hostbound.Injection{{Header: "Authorization", Prefix: "Bearer "}},
			Token:   func(context.Context) (string, error) { return apiToken, nil }},
		{ID: "GIT_TOKEN", Hosts: []string{"github.com"}, Placeholder: "git-placeholder",
			Injects: []hostbound.Injection{{BasicUser: "x-access-token"}},
			Token:   func(context.Context) (string, error) { return gitToken, nil }},
	}
	p, err := hostbound.New(hostbound.Config{Bindings: bindings, ScanResponses: true})
	if err != nil {
		return err
	}
	defer p.Close()

	ca, bundle, err := p.WriteCAFiles(dir, rootsPEM)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(ln) }()

	cmd := exec.Command("git", "ls-remote", repo)
	cmd.Env = hostbound.ClientEnv(os.Environ(), "http://"+ln.Addr().String(), ca, bundle, bindings)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err = cmd.Run()
	p.Close()
	return errors.Join(err, <-served)
}
```

Each binding ID names the child environment variable that receives its placeholder.
Keep real credentials out of the rest of the child environment.
Use `NewPlaceholder` to generate a random placeholder for a binding.

## Injection forms

`Binding.Injects` lists the forms in priority order. The first form carrying the binding's placeholder or a granted placeholder receives the token.

- `Injection{Header: "Authorization", Prefix: "Bearer "}` matches the whole header value. Omit `Prefix` for a header containing just the placeholder.
- `Injection{BasicUser: "x-access-token"}` matches HTTP Basic authentication with that user name and the placeholder as the password.
- `Injection{Path: true}` replaces literal occurrences in the escaped request path. For example, `/botPLACEHOLDER/sendMessage` can become `/bot123:example-token/sendMessage`, and `/PLACEHOLDER` can become `/api/webhooks/123/example`. The token may contain letters, digits, `-._~`, `/` and `:`. The proxy refuses percent-encoded placeholders and overlapping substitutions. The query string is outside the path form.

Repeating the same placeholder in a path uses a single `Check` and token lookup. A path form that would substitute two distinct placeholders for the same binding is refused before `Check`.

`Binding.PathPrefixes` limits every injection form to paths that equal a prefix or continue with `/` or `:`.
For example, `/v4/spreadsheets/A` allows both `/v4/spreadsheets/A:batchUpdate` and `/v4/spreadsheets/A/values/Sheet1!A1:append`.
With prefixes set, a path containing a `.` or `..` segment, a percent-encoded slash, or a percent-encoded dot is outside the binding.
An out-of-scope request passes through without that binding's token if its checks allow the request.
If substitution would put the path outside any injected binding's prefixes, the proxy refuses the request. `Use.Path` records the client's escaped path before substitution.

## Checks and grants

A binding's `Check` function runs before the proxy gets the credential.
It receives the request and the placeholder that the request presented.
If it returns an error, the proxy refuses the request and does not call `Token`.
A `*Refusal` error sets the status, headers and body of the response.

`Grant` gives a binding an extra placeholder until the caller revokes it.
Revoking a grant also cancels the requests in progress that received the credential through it.
A `Check` function can then allow some requests only with a granted placeholder.
For example, an application can give a command that a person approved its own placeholder, and refuse write requests that present the usual placeholder.

```go
// Inside Run, before hostbound.New: refuse methods other than GET and HEAD
// unless the request presents a granted placeholder.
git := &bindings[1]
git.Check = func(r *http.Request, presented string) error {
	if presented != git.Placeholder || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil
	}
	return &hostbound.Refusal{Status: http.StatusForbidden, Body: []byte("write not approved\n"), Reason: "write not approved"}
}

// After hostbound.New: give one approved command its own placeholder.
grant, err := hostbound.NewPlaceholder("GIT_TOKEN")
if err != nil {
	return err
}
revoke, err := p.Grant("GIT_TOKEN", grant)
if err != nil {
	return err
}
defer revoke()
// Run the approved command with grant in place of the placeholder.
```

## Client settings

Set `HTTPS_PROXY` to the proxy URL. The CA bundle contains the system roots plus the proxy CA.

| Client | Settings in addition to `HTTPS_PROXY` |
| --- | --- |
| curl 8.5.0 | `CURL_CA_BUNDLE` points to the bundle. |
| Node 24.22.2 `fetch` | `NODE_USE_ENV_PROXY=1` enables proxy settings. `NODE_EXTRA_CA_CERTS` points to the proxy CA. |
| Python 3.12 `requests` 2.31 | `REQUESTS_CA_BUNDLE` points to the bundle. |
| Python 3.12 `urllib` | `SSL_CERT_FILE` points to the bundle. |
| Go 1.26 `net/http` | The compatibility run supplied the roots through `tls.Config`. A stock client reads `SSL_CERT_FILE`. No test covers that path. |
| git 2.43 | `GIT_SSL_CAINFO` points to the bundle. `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n` configure a host-specific credential helper that returns the user name of the binding's first Basic form and the placeholder. |

`ClientEnv` sets these environment variables, including the git helper variables for Basic-auth bindings.
It also sets lowercase proxy variables and adds loopback addresses to `NO_PROXY` and `no_proxy`.
The versions in the table are the ones a compatibility run used before the code moved to this repository. The tests in this repository run `curl`, `git` and Python's `urllib`.
Java and NSS trust stores are untested.
A client that ignores `HTTPS_PROXY` or pins the upstream certificate cannot use this setup for a bound host.

## What it guarantees

1. **Credential destination.** The proxy sends a credential only to a host named by its binding, over verified TLS on port 443.
   The `CONNECT` target, the TLS server name (SNI) and each request's effective `Host` (or `:authority`) must name the same bound host.
   Use an origin-form or absolute-form request target.
   The proxy refuses opaque targets and nested `CONNECT` requests before fetching a token.
   It substitutes the credential only when a declared form matches the binding's placeholder or a granted placeholder, the path is allowed by the binding, and `Check` allows the request.
2. **Response reflection.** With `ScanResponses` on, the proxy replaces matching credentials with placeholders in bound hosts' HTTP responses.
   It scans header names and values, interim responses, trailers and the body, including matches split across reads.
3. **Destination addresses.** The default dialer never connects to addresses on its deny list.
   It checks each candidate address when making the connection, after name resolution.
   The default list includes loopback, private, link-local, shared carrier-grade NAT, multicast, unspecified, documentation, benchmarking and other special-purpose ranges.
   `DenyPrefixes` adds ranges. A custom `DialContext` replaces the default check.

## What it does not protect

- Signing schemes that keep the key on the client, such as AWS SigV4 and HMAC, need a signer.
- A credential in a query string or request body is outside the injection forms.
- Substitution works on HTTP requests. Protocols such as SSH, SMTP and PostgreSQL need their own credential handling.
- A secret used inside the program, such as a file encryption key or a commit signing key, stays outside the proxy's scope. A binding also needs a named host.
- Response scanning ends at a protocol upgrade. For example, WebSocket frames pass through unchanged.
- An upstream can return a re-encoded credential, such as one with URL or JSON escapes. Response scanning matches credential representations it knows.
- The program can call the API on bound hosts while it runs, with the permissions of the credential. A `Check` function can refuse some of those requests.
- The scanner keeps a history of four recently used tokens per binding. Older rotated tokens can pass through on later requests. The proxy still scans each response for the token it sent with that request.
- The proxy has no connection limit. Idle tunnels to unbound hosts have no timeout.
- `Token` returns the current credential once per matching request that `Check` allows, and must honor the request context. `Close` can return while a callback that ignores cancellation is still running.
- `Record` receives a `Use` record for each request to a bound host. The callback must return without blocking.
- Go's HTTP transport can write upstream bytes to the process's default logger on an idle connection. Those bytes can contain a credential.
- The CA's DNS name constraints also permit subdomains of bound names. The proxy issues leaf certificates only for exact bound names.

## How it was tested

The verification used unit tests with the race detector, fuzz tests for header matching, path substitution, path limits and authority checks, and property tests for response scanning.
Two verification rounds used inputs chosen to make the three guarantees fail.
The first round ran on the first version and found six failing cases. Five returned all or part of the credential to the client with response scanning on. One accepted a connection inside a configured deny prefix.
Five were fixed. The sixth, bytes after a protocol upgrade, is a limit listed above.
The second round found two more defects. All seven fixes have regression tests.

- An opaque request target such as `x:https://other.example/a` passed the authority check. The proxy now refuses it before it fetches a token.
- The `CONNECT` request header had no size limit. The proxy now limits it to 64 KiB.

No outside party has audited the code.

The prototype measurements used loopback on one AMD EPYC 9354P machine with 8 vCPUs and Go 1.26.11. One-minute load ranged from 0.81 to 1.43.

- Latency increased by about 0.3 to 0.7 ms per request, with 200 sequential requests per test case. For Go with a reused connection, median latency was 0.19 ms direct and 0.45 ms through the proxy.
- A 100 MiB download over HTTP/2 ran at 247 MiB/s direct. Through the proxy it ran at 194 MiB/s with scanning off and 163 MiB/s with scanning on. Each figure comes from one run.
- A clone of a small git repository took 0.107 s direct and 0.112 s through the proxy, with one clone per case.

The second round also measured scanner throughput on a 16 MiB body at a load of 4.2, with one run per case.
It measured 2,082 MiB/s for ordinary text, 118 MiB/s for a repeated 32-byte token and 41 MiB/s for a repeated 8-byte token.
A 0.5 MiB gzip response expanded to 512 MiB and streamed in 0.8 s with about 10 MiB of heap growth.

## Status, security reports, license

hostbound is version 0.x. The API can change.
Report security problems through the repository's [private vulnerability reporting](https://github.com/plori-ai/hostbound/security/advisories/new).
The library uses the [MIT license](LICENSE).
