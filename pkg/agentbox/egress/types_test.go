package egress

import "net/netip"

type netipAddr = netip.Addr

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
