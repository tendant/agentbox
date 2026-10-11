//go:build linux

package gvisor

// NetworkGateway's network namespace. agentbox re-runs its own binary as
// "<exe> __agentbox-netns GATEWAY -- RUNSC ARGS..." under "unshare -Urn"
// (agentbox-unshare where AppArmor restricts user namespaces): root in a new
// user and network namespace, it gives the namespace loopback and a default
// route that leads nowhere, has nftables send every TCP connection to the
// catcher and DNS to the responder, drops everything else, and then runs
// "runsc --network=host" there, staying as its parent. The catcher hands
// each connection to the gateway's Unix socket, outside the namespace.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

const (
	catchAddr = "127.0.0.1:15001"
	dnsAddr   = "127.0.0.1:15053"
)

// The nftables rules: DNS to the responder wherever it was sent (the host's
// resolv.conf may name 127.0.0.53), loopback as is, all other TCP to the
// catcher; nothing else leaves (UDP, ICMP, IPv6). The filter admits the
// redirected packets by their conntrack state: it sees them before they are
// rerouted to lo.
const nftRules = `
table ip agentbox {
  chain nat_out {
    type nat hook output priority -100; policy accept;
    udp dport 53 redirect to :15053
    tcp dport 53 redirect to :15053
    ip daddr 127.0.0.0/8 accept
    meta l4proto tcp redirect to :15001
  }
  chain filter_out {
    type filter hook output priority 0; policy drop;
    ct status dnat accept
    oifname "lo" accept
  }
}
table ip6 agentbox6 {
  chain filter_out {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
  }
}
`

func init() {
	if len(os.Args) > 1 && os.Args[1] == netnsArg {
		os.Exit(netnsMain(os.Args[2:]))
	}
}

// netnsMain is the helper: "--probe" sets the namespace up and exits.
func netnsMain(args []string) int {
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "agentbox netns:", err)
		return 1
	}
	if err := setupNetns(); err != nil {
		return fail(err)
	}
	if len(args) == 1 && args[0] == "--probe" {
		return 0
	}
	if len(args) < 3 || args[1] != "--" {
		return fail(errors.New("usage: " + netnsArg + " GATEWAY -- CMD..."))
	}
	gateway, argv := args[0], args[2:]
	if err := serveCatcher(gateway); err != nil {
		return fail(err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

func setupNetns() error {
	ip, err := tool("ip")
	if err != nil {
		return err
	}
	nft, err := tool("nft")
	if err != nil {
		return err
	}
	for _, a := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "agentbox0", "type", "dummy"},
		{"addr", "add", "10.255.255.1/24", "dev", "agentbox0"},
		{"link", "set", "agentbox0", "up"},
		{"route", "add", "default", "dev", "agentbox0"},
	} {
		if out, err := exec.Command(ip, a...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %s", strings.Join(a, " "), strings.TrimSpace(string(out)))
		}
	}
	c := exec.Command(nft, "-f", "-")
	c.Stdin = strings.NewReader(nftRules)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %s", strings.TrimSpace(string(out)))
	}
	// Belt and braces: the rules already drop IPv6.
	os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1"), 0)
	return nil
}

// tool finds ip or nft, in sbin too (not on a normal user's PATH on Debian).
func tool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, d := range []string{"/usr/sbin", "/sbin"} {
		if _, err := os.Stat(d + "/" + name); err == nil {
			return d + "/" + name, nil
		}
	}
	return "", fmt.Errorf("%s not found (apt install iproute2 nftables)", name)
}

// serveCatcher starts the catcher and the DNS responder (UDP and TCP).
func serveCatcher(gateway string) error {
	f := newFakeDNS()
	tl, err := net.Listen("tcp", catchAddr)
	if err != nil {
		return err
	}
	ul, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		return err
	}
	dl, err := net.Listen("tcp", dnsAddr)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*net.TCPConn)
				dst, err := originalDst(tc)
				if err != nil {
					tc.SetLinger(0)
					tc.Close()
					return
				}
				target, head, ok := f.target(tc, dst)
				if !ok {
					tc.SetLinger(0)
					tc.Close()
					return
				}
				relay(tc, gateway, target, head)
			}()
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := f.answer(buf[:n]); r != nil {
				ul.WriteTo(r, from)
			}
		}
	}()
	go func() {
		for {
			c, err := dl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				for {
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					r := f.answer(q)
					if r == nil {
						return
					}
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
				}
			}()
		}
	}()
	return nil
}

// originalDst is where a redirected connection was going (SO_ORIGINAL_DST).
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var m *syscall.IPv6Mreq
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		m, gerr = syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, 80) // SO_ORIGINAL_DST
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if gerr != nil {
		return netip.AddrPort{}, gerr
	}
	// a sockaddr_in: family, port (big-endian), address
	b := m.Multiaddr
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[2:4])), nil
}
