package hostbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestGuardRanges(t *testing.T) {
	d := guardedDialer(nil)
	for _, tc := range []struct {
		addr   string
		denied bool
	}{
		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"192.0.2.1", true},
		{"::ffff:192.0.2.1", true},
		{"169.254.0.1", true},
		{"fe80::1", true},
		{"fe80::1%eth0", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"fc00::1", true},
		{"fd12:3456::1", true},
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"::", true},
		{"224.0.0.1", true},
		{"239.255.255.250", true},
		{"ff02::1", true},
		{"255.255.255.255", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:0.0.0.0", true},
		{"64:ff9b::a9fe:a9fe", true},
		{"64:ff9b::7f00:1", true},
		{"203.0.113.9", true},
		{"::ffff:203.0.113.9", true},
		{"198.51.100.20", true},
		{"192.0.0.23", true},
		{"198.19.255.254", true},
		{"198.51.100.42", true},
		{"203.0.113.42", true},
		{"192.88.99.2", true},
		{"fec0::1", true},
		{"64:ff9b:1::808:808", true},
		{"2002:808:808::1", true},
		{"2001::cafe", true},
		{"::808:808", true},
		{"2001:db8::1", true},
		{"100::1", true},
		{"100:0:0:1::1", true},
		{"2001:2::1", true},
		{"3fff:fff::1", true},
		{"5f00::1", true},
		{"2001:1::1", true},
		{"2001:1::2", true},
		{"2001:1::3", true},
		{"2001:3::5", true},
		{"2001:4:112::1", true},
		{"2001:20::1", true},
		{"2001:30::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"100.128.0.1", false},
		{"172.32.0.1", false},
		{"9.9.9.9", false},
		{"2606:4700::1111", false},
		{"::ffff:8.8.8.8", false},
		{"64:ff9b::808:808", false},
	} {
		err := d.ControlContext(context.Background(), "tcp", net.JoinHostPort(tc.addr, "443"), nil)
		if got := errors.Is(err, errDenied); got != tc.denied {
			t.Errorf("%s: denied=%v, want %v", tc.addr, got, tc.denied)
		}
	}
}

func fakeDNS(addrs ...netip.Addr) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			var n uint16
			if binary.Read(server, binary.BigEndian, &n) != nil {
				return
			}
			q := make([]byte, n)
			if _, err := io.ReadFull(server, q); err != nil {
				return
			}
			end := 12
			for q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			resp := append([]byte{q[0], q[1], 0x81, 0x80, 0, 1, 0, byte(len(addrs)), 0, 0, 0, 0}, q[12:end]...)
			for _, a := range addrs {
				ip := a.As4()
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, ip[:]...)
			}
			_ = binary.Write(server, binary.BigEndian, uint16(len(resp)))
			_, _ = server.Write(resp)
		}()
		return client, nil
	}
}

func TestGuardChecksEveryResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	for _, tc := range []struct {
		name    string
		addrs   []netip.Addr
		allowed []string
	}{
		{"allowed and denied", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("8.8.8.8")}, []string{"8.8.8.8"}},
		{"denied only", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := guardedDialer(nil)
			d.Timeout = 2 * time.Second
			d.Resolver = &net.Resolver{PreferGo: true, Dial: fakeDNS(tc.addrs...)}
			var mu sync.Mutex
			checked := map[string]bool{}
			guard := d.ControlContext
			d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
				err := guard(ctx, network, address, c)
				mu.Lock()
				checked[address] = err == nil
				mu.Unlock()
				if err == nil && address != ln.Addr().String() {
					return errors.New("test stopped the allowed dial")
				}
				return err
			}
			_, err := d.DialContext(context.Background(), "tcp4", "multi.test.:"+port)
			if err == nil {
				t.Fatal("dial succeeded")
			}
			if tc.allowed == nil && !errors.Is(err, errDenied) {
				t.Fatalf("error %v, want errDenied", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(checked) != len(tc.addrs) {
				t.Fatalf("guard checked %v, want every one of %v", checked, tc.addrs)
			}
			for _, a := range tc.addrs {
				want := false
				for _, ok := range tc.allowed {
					want = want || ok == a.String()
				}
				if got, ok := checked[net.JoinHostPort(a.String(), port)]; !ok || got != want {
					t.Fatalf("%s: checked=%v allowed=%v, want allowed=%v", a, ok, got, want)
				}
			}
		})
	}
	select {
	case <-accepted:
		t.Fatal("the denied loopback listener accepted a connection")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestGuardDenyPrefixMatchesEveryAddressForm(t *testing.T) {
	for _, tc := range []struct{ prefix, addr string }{
		{"::ffff:8.8.8.0/120", "8.8.8.27"},
		{"64:ff9b::808:800/120", "64:ff9b::808:81b"},
		{"8.8.8.0/24", "64:ff9b::808:81b"},
		{"::ffff:8.8.8.0/120", "::ffff:8.8.8.27"},
		{"8.8.8.0/24", "::ffff:8.8.8.27"},
	} {
		addr := net.JoinHostPort(tc.addr, "443")
		if err := guardedDialer(nil).ControlContext(context.Background(), "tcp", addr, nil); err != nil {
			t.Fatalf("%s denied without a configured prefix: %v", tc.addr, err)
		}
		d := guardedDialer([]netip.Prefix{netip.MustParsePrefix(tc.prefix)})
		if err := d.ControlContext(context.Background(), "tcp", addr, nil); !errors.Is(err, errDenied) {
			t.Errorf("%s with DenyPrefixes %s: %v", tc.addr, tc.prefix, err)
		}
	}
}
