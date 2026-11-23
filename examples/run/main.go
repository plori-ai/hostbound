// Command run executes a child with host-bound bearer credentials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/plori-ai/hostbound"
)

func main() {
	if err := run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var bindings []hostbound.Binding
	flag.Func("bind", "NAME=host[,host] for a bearer token (repeatable)", func(arg string) error {
		name, hosts, ok := strings.Cut(arg, "=")
		if !ok || name == "" || hosts == "" {
			return fmt.Errorf("expected NAME=host[,host]")
		}
		value := os.Getenv(name)
		if value == "" {
			return fmt.Errorf("environment variable %q is empty or unset", name)
		}
		placeholder, err := hostbound.NewPlaceholder(name)
		if err != nil {
			return err
		}
		bindings = append(bindings, hostbound.Binding{
			ID: name, Hosts: strings.Split(hosts, ","), Placeholder: placeholder,
			Injects: []hostbound.Injection{{Header: "Authorization", Prefix: "Bearer "}},
			Token:   func(context.Context) (string, error) { return value, nil },
		})
		return nil
	})
	flag.Parse()
	if len(bindings) == 0 || flag.NArg() == 0 {
		return errors.New("usage: run -bind NAME=host[,host] [-bind ...] -- command [arg ...]")
	}

	roots, err := readRoots()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "hostbound-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p, err := hostbound.New(hostbound.Config{Bindings: bindings, ScanResponses: true})
	if err != nil {
		return err
	}
	defer p.Close()
	ca, bundle, err := p.WriteCAFiles(dir, roots)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(ln) }()
	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.Env = hostbound.ClientEnv(os.Environ(), "http://"+ln.Addr().String(), ca, bundle, bindings)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	p.Close()
	return errors.Join(err, <-served)
}

func readRoots() ([]byte, error) {
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		return os.ReadFile(path)
	}
	for _, path := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	} {
		if roots, err := os.ReadFile(path); err == nil {
			return roots, nil
		}
	}
	return nil, errors.New("set SSL_CERT_FILE to a readable PEM root bundle")
}
