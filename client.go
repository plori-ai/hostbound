package hostbound

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// NewPlaceholder returns "hostbound-" followed by name, a hyphen and 32 random hex digits.
func NewPlaceholder(name string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "hostbound-" + name + "-" + hex.EncodeToString(b[:]), nil
}

// WriteCAFiles creates proxy-ca.pem and ca-bundle.pem with mode 0600 in an existing
// directory owned by the caller. The bundle contains rootsPEM followed by the proxy CA.
// Pass the system roots in rootsPEM: with an empty rootsPEM a client that uses the
// bundle can verify only bound hosts.
// Both names must be unused. The caller owns the returned paths and their cleanup.
func (p *Proxy) WriteCAFiles(dir string, rootsPEM []byte) (caFile, bundleFile string, err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	caFile = filepath.Join(dir, "proxy-ca.pem")
	bundleFile = filepath.Join(dir, "ca-bundle.pem")
	ca := p.CACertPEM()
	if err := writeNewFile(caFile, ca); err != nil {
		return "", "", err
	}
	if err := writeNewFile(bundleFile, slices.Concat(rootsPEM, []byte("\n"), ca)); err != nil {
		return "", "", errors.Join(err, os.Remove(caFile))
	}
	return caFile, bundleFile, nil
}

func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Close()); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}

// ClientEnv returns a copy of env configured for the proxy, CA files and git helpers.
// Each binding's ID names the variable that receives its placeholder. With no bindings
// it returns a copy of env as supplied. It never calls a binding's Token function.
func ClientEnv(env []string, proxyURL, caFile, bundleFile string, bindings []Binding) []string {
	env = slices.Clone(env)
	if len(bindings) == 0 {
		return env
	}
	for _, b := range bindings {
		env = setEnv(env, b.ID, b.Placeholder)
	}
	for _, key := range []string{"HTTPS_PROXY", "https_proxy"} {
		env = setEnv(env, key, proxyURL)
	}
	noProxy := mergeNoProxy(env)
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		env = setEnv(env, key, noProxy)
	}
	env = setEnv(env, "NODE_USE_ENV_PROXY", "1")
	for _, key := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		env = setEnv(env, key, bundleFile)
	}
	env = setEnv(env, "NODE_EXTRA_CA_CERTS", caFile)
	return applyGitHelpers(env, bindings)
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	env = slices.DeleteFunc(env, func(entry string) bool { return strings.HasPrefix(entry, prefix) })
	return append(env, prefix+value)
}

func lastEnvValue(env []string, key string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if value, ok := strings.CutPrefix(env[i], key+"="); ok {
			return value
		}
	}
	return ""
}

func mergeNoProxy(env []string) string {
	var entries []string
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		for entry := range strings.SplitSeq(lastEnvValue(env, key), ",") {
			if entry = strings.TrimSpace(entry); entry != "" && !slices.Contains(entries, entry) {
				entries = append(entries, entry)
			}
		}
	}
	for _, entry := range []string{"localhost", "127.0.0.1", "::1"} {
		if !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, ",")
}

func applyGitHelpers(env []string, bindings []Binding) []string {
	n, err := strconv.Atoi(lastEnvValue(env, "GIT_CONFIG_COUNT"))
	if err != nil || n < 0 {
		n = 0
	}
	start := n
	for _, b := range bindings {
		i := slices.IndexFunc(b.Injects, func(inj Injection) bool { return inj.BasicUser != "" })
		if i < 0 {
			continue
		}
		helper := "!f() { printf '%s\\n' " + shellQuote("username="+b.Injects[i].BasicUser) + " " + shellQuote("password="+b.Placeholder) + "; }; f"
		for _, host := range b.Hosts {
			key := "credential.https://" + host + ".helper"
			// An empty value tells git to discard helpers inherited for this host.
			for _, value := range []string{"", helper} {
				env = setEnv(env, "GIT_CONFIG_KEY_"+strconv.Itoa(n), key)
				env = setEnv(env, "GIT_CONFIG_VALUE_"+strconv.Itoa(n), value)
				n++
			}
		}
	}
	if n == start {
		return env
	}
	return setEnv(env, "GIT_CONFIG_COUNT", strconv.Itoa(n))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
