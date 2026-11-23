package hostbound

import (
	"net/netip"
	"strconv"
	"strings"
)

const boundPort = "443"

func parseAuthority(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", false
		}
		addr, err := netip.ParseAddr(s[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", false
		}
		if port, ok = parsePort(s[end+1:]); !ok {
			return "", "", false
		}
		return addr.String(), port, true
	}
	host = s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		host = s[:i]
		if port, ok = parsePort(s[i:]); !ok {
			return "", "", false
		}
	}
	if host, ok = normalizeName(host); !ok {
		return "", "", false
	}
	return host, port, true
}

func parsePort(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	p := s[1:]
	if s[0] != ':' || p == "" || len(p) > 5 {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return "", false
		}
	}
	if n, _ := strconv.Atoi(p); n < 1 || n > 65535 {
		return "", false
	}
	return p, true
}

func normalizeName(h string) (string, bool) {
	h = strings.TrimSuffix(h, ".")
	if h == "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return "", false
	}
	b := []byte(h)
	for i, c := range b {
		switch {
		case 'A' <= c && c <= 'Z':
			b[i] = c + 'a' - 'A'
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.', c == '_':
		default:
			return "", false
		}
	}
	return string(b), true
}

func sameAuthority(bound, authority string) bool {
	host, port, ok := parseAuthority(authority)
	return ok && host == bound && (port == "" || port == boundPort)
}
