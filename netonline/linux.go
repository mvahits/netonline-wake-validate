
//go:build linux
// +build linux

package netonline

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func startOSEventStream(ctx context.Context) (<-chan osEvent, <-chan error) {
	out := make(chan osEvent, 8)
	errc := make(chan error, 1)
	go func() {
		defer close(out); defer close(errc)
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
		if err != nil { errc <- fmt.Errorf("netlink socket: %w", err); return }
		defer unix.Close(fd)
		sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE}
		if err := unix.Bind(fd, sa); err != nil { errc <- fmt.Errorf("netlink bind: %w", err); return }
		buf := make([]byte, 1<<16)
		for {
			select { case <-ctx.Done(): return; default: }
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EINTR) { continue }
				errc <- fmt.Errorf("netlink recv: %w", err); return
			}
			msgs, err := parseNlMsgs(buf[:n]); if err != nil { errc <- err; continue }
			for _, m := range msgs {
				switch m.Header.Type {
				case unix.RTM_NEWROUTE, unix.RTM_DELROUTE: out <- osEvent{reason: "route change"}
				case unix.RTM_NEWADDR, unix.RTM_DELADDR:   out <- osEvent{reason: "addr change"}
				case unix.RTM_NEWLINK, unix.RTM_DELLINK:   out <- osEvent{reason: "link change"}
				}
			}
		}
	}()
	return out, errc
}

type nlmsghdr struct { Len uint32; Type uint16; Flags uint16; Seq uint32; Pid uint32 }
type nlmsg struct { Header nlmsghdr; Body []byte }

func parseNlMsgs(b []byte) ([]nlmsg, error) {
	var out []nlmsg
	const hdrLen = int(unsafe.Sizeof(nlmsghdr{}))
	for len(b) >= hdrLen {
		h := *(*nlmsghdr)(unsafe.Pointer(&b[0]))
		if h.Len < uint32(hdrLen) || int(h.Len) > len(b) { return out, fmt.Errorf("invalid nlmsg len") }
		body := b[hdrLen:h.Len]
		out = append(out, nlmsg{Header: h, Body: body})
		adv := int((h.Len + 3) &^ 3)
		if adv > len(b) { break }
		b = b[adv:]
	}
	return out, nil
}

func recomputeOnline() (bool, string, error) {
	hasDef, ifname, gw, err := linuxDefaultRoute()
	if err != nil { return false, "default route check failed", err }
	if !hasDef { return false, "no default route", nil }
	if ifname == "" { return false, "default route no iface", nil }
	up, err := linuxIfaceUp(ifname); if err != nil { return false, "iface state check failed", err }
	if !up { return false, "default iface down", nil }
	if !ifaceHasUsableAddr(ifname) { return false, "default iface has no usable IP", nil }
	if gw != "" && !arpIsReady(gw, ifname) { return false, "gateway neighbor not ready", nil }
	if !hasDNSResolver() { return false, "no DNS resolver", nil }
	return true, "default via " + ifname, nil
}

func linuxDefaultRoute() (bool, string, string, error) {
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f); if sc.Scan() {}
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 11 { continue }
			iface := fields[0]; destHex := fields[1]; flagsStr := fields[3]; gwHex := fields[2]
			if destHex == "00000000" {
				flags, _ := strconv.ParseInt(flagsStr, 16, 64)
				if flags&0x1 != 0 {
					gw := hexToIPv4(gwHex)
					return true, iface, gw, nil
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, ln := range lines {
			ln = strings.TrimSpace(ln); if ln == "" { continue }
			fields := strings.Fields(ln); if len(fields) < 10 { continue }
			pfxLenHex := fields[1]
			if pfxLenHex == "000" {
				ifIdxHex := fields[9]
				ifidx, _ := strconv.ParseInt(ifIdxHex, 16, 32)
				ifname := ifIndexToName(int(ifidx))
				return true, ifname, "", nil
			}
		}
	}
	return false, "", "", nil
}

func hexToIPv4(hexs string) string {
	if len(hexs) != 8 { return "" }
	b0 := hexs[0:2]; b1 := hexs[2:4]; b2 := hexs[4:6]; b3 := hexs[6:8]
	bs := []string{b3, b2, b1, b0}
	octets := make([]byte, 0, 4)
	for _, h := range bs {
		v, err := strconv.ParseUint(h, 16, 8); if err != nil { return "" }
		octets = append(octets, byte(v))
	}
	return fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3])
}

func arpIsReady(gw string, ifname string) bool {
	ip := net.ParseIP(gw)
	if ip == nil || ip.To4() == nil { return true }
	b, err := os.ReadFile("/proc/net/arp"); if err != nil { return true }
	lines := strings.Split(string(b), "\n")
	for i, ln := range lines {
		if i == 0 { continue }
		f := strings.Fields(strings.TrimSpace(ln)); if len(f) < 6 { continue }
		ipf, flags, mac, dev := f[0], f[2], f[3], f[5]
		if dev != ifname || ipf != gw { continue }
		val, _ := strconv.ParseInt(flags, 0, 64)
		if (val & 0x2) == 0 { return false }
		if mac == "00:00:00:00:00:00" { return false }
		return true
	}
	return false
}

func ifIndexToName(idx int) string {
	ifaces, _ := net.Interfaces()
	for _, it := range ifaces { if it.Index == idx { return it.Name } }
	return ""
}

func linuxIfaceUp(name string) (bool, error) {
	if name == "" { return false, nil }
	ifi, err := net.InterfaceByName(name)
	if err == nil {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 { return false, nil }
	}
	oper := filepath.Join("/sys/class/net", name, "operstate")
	if b, err := os.ReadFile(oper); err == nil {
		s := strings.TrimSpace(string(b)); if s != "up" && s != "unknown" { return false, nil }
	}
	carrier := filepath.Join("/sys/class/net", name, "carrier")
	if b, err := os.ReadFile(carrier); err == nil {
		if strings.TrimSpace(string(b)) != "1" { return false, nil }
	}
	return true, nil
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
