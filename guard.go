package hostbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var errDenied = errors.New("hostbound: destination address denied")

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), // Documentation (TEST-NET-1).
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

func denyList(extra []netip.Prefix) []netip.Prefix {
	list := append([]netip.Prefix(nil), deniedPrefixes...)
	for _, p := range extra {
		list = append(list, p.Masked())
		if a := p.Addr(); a.Is4In6() {
			list = append(list, netip.PrefixFrom(a.Unmap(), max(p.Bits()-96, 0)).Masked())
		}
	}
	return list
}

func deniedAddr(a netip.Addr, deny []netip.Prefix) bool {
	if !a.IsValid() {
		return true
	}
	a = a.WithZone("")
	forms := []netip.Addr{a, a.Unmap()}
	if nat64Prefix.Contains(a) {
		b := a.As16()
		forms = append(forms, netip.AddrFrom4([4]byte(b[12:])))
	}
	for _, f := range forms {
		for _, p := range deny {
			if p.Contains(f) {
				return true
			}
		}
	}
	return false
}

func guardedDialer(extra []netip.Prefix) *net.Dialer {
	deny := denyList(extra)
	return &net.Dialer{
		Timeout: 10 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || deniedAddr(ap.Addr(), deny) {
				return fmt.Errorf("%w: %s", errDenied, address)
			}
			return nil
		},
	}
}
