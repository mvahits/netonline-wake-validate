
//go:build freebsd || darwin
// +build freebsd darwin

package netonline

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func startOSEventStream(ctx context.Context) (<-chan osEvent, <-chan error) {
	out := make(chan osEvent, 8)
	errc := make(chan error, 1)
	go func() {
		defer close(out); defer close(errc)
		fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
		if err != nil { errc <- fmt.Errorf("route socket: %w", err); return }
		defer unix.Close(fd)
		buf := make([]byte, 1<<16)
		for {
			select { case <-ctx.Done(): return; default: }
			n, err := unix.Read(fd, buf)
			if err != nil { errc <- fmt.Errorf("route recv: %w", err); return }
			if _, err := route.ParseRIB(route.RIBTypeKernel, buf[:n]); err != nil {
				out <- osEvent{reason: "net change"}; continue
			}
			out <- osEvent{reason: "net change"}
		}
	}()
	return out, errc
}

func recomputeOnline() (bool, string, error) {
	hasDef, ifname, err := bsdDefaultRoute()
	if err != nil { return false, "default route check failed", err }
	if !hasDef { return false, "no default route", nil }
	if ifname == "" { return false, "default route no iface", nil }
	ifi, err := net.InterfaceByName(ifname)
	if err != nil || (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 { return false, "default iface down/loopback", nil }
	if !ifaceHasUsableAddr(ifname) { return false, "default iface has no usable IP", nil }
	if !hasDNSResolver() { return false, "no DNS resolver", nil }
	return true, "default via " + ifname, nil
}

func bsdDefaultRoute() (bool, string, error) {
	msgs, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err == nil { if ok, ifn := pickDefaultFromRIB(msgs); ok { return true, ifn, nil } }
	msgs6, err := route.FetchRIB(unix.AF_INET6, route.RIBTypeRoute, 0)
	if err == nil { if ok, ifn := pickDefaultFromRIB(msgs6); ok { return true, ifn, nil } }
	return false, "", nil
}

func pickDefaultFromRIB(b []byte) (bool, string) {
	ms, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil { return false, "" }
	for _, m := range ms {
		rm, ok := m.(*route.RouteMessage); if !ok { continue }
		var dst route.Addr
		for i, a := range rm.Addrs { if i == route.RTAB_DST { dst = a; break } }
		if isZeroAddr(dst) { return true, ifNameFromIndex(rm.Index) }
	}
	return false, ""
}

func isZeroAddr(a route.Addr) bool {
	switch t := a.(type) {
	case *route.Inet4Addr:
		return t.IP[0]|t.IP[1]|t.IP[2]|t.IP[3] == 0
	case *route.Inet6Addr:
		var s byte; for _, b := range t.IP { s |= b }; return s == 0
	default:
		return false
	}
}

func ifNameFromIndex(idx int) string {
	ifi, err := net.InterfaceByIndex(idx); if err != nil { return "" }
	return ifi.Name
}

func ifaceHasUsableAddr(ifname string) bool {
	ifi, err := net.InterfaceByName(ifname); if err != nil { return false }
	addrs, err := ifi.Addrs(); if err != nil { return false }
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) { case *net.IPNet: ip = v.IP; case *net.IPAddr: ip = v.IP }
		if ip == nil || ip.IsLoopback() { continue }
		if v4 := ip.To4(); v4 != nil { if !v4.IsUnspecified() { return true }; continue }
		if ip.IsLinkLocalUnicast() || ip.IsUnspecified() { continue }
		return true
	}
	return false
}
