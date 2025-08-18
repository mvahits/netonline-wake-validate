
//go:build windows
// +build windows

package netonline

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

type handle = uintptr

var (
	iphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = iphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = iphlpapi.NewProc("CancelMibChangeNotify2")
	procGetAdaptersAddresses    = iphlpapi.NewProc("GetAdaptersAddresses")
)

const AF_UNSPEC = 0

func startOSEventStream(ctx context.Context) (<-chan osEvent, <-chan error) {
	out := make(chan osEvent, 8)
	errc := make(chan error, 1)
	go func() {
		defer close(out); defer close(errc)
		var h handle
		cb := windows.NewCallback(func(callerCtx uintptr, row uintptr, notificationType uint32) uintptr {
			select { case out <- osEvent{reason: "ip interface change"}: default: }
			return 0
		})
		r1, _, e := procNotifyIpInterfaceChange.Call(uintptr(AF_UNSPEC), cb, 0, uintptr(1), uintptr(unsafe.Pointer(&h)))
		if r1 != 0 { errc <- fmt.Errorf("NotifyIpInterfaceChange failed: %v", e); return }
		defer procCancelMibChangeNotify2.Call(uintptr(h))
		<-ctx.Done()
	}()
	return out, errc
}

func recomputeOnline() (bool, string, error) {
	hasDef, ifn, err := winDefaultRouteAndIface()
	if err != nil { return false, "default route check failed", err }
	if hasDef && ifn != "" {
		ifi, err := net.InterfaceByName(ifn)
		if err != nil || (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 { return false, "default iface down/loopback", nil }
		if !ifaceHasUsableAddr(ifn) { return false, "default iface has no usable IP", nil }
		if !winHasDNS() { return false, "no DNS resolver", nil }
		return true, "default via " + ifn, nil
	}
	alt, ok := winPickUpGlobalInterface()
	if !ok { return false, "no default route", nil }
	if !winHasDNS() { return false, "no DNS resolver", nil }
	return true, "fallback: up iface " + alt, nil
}

const (
	GAA_FLAG_SKIP_ANYCAST     = 0x2
	GAA_FLAG_SKIP_MULTICAST   = 0x4
	GAA_FLAG_INCLUDE_GATEWAYS = 0x80
)

type ipAdapterAddresses struct {
	Length uint32; IfIndex uint32; Next *ipAdapterAddresses
	AdapterName *byte
	FirstUnicastAddress uintptr
	FirstAnycastAddress uintptr
	FirstMulticastAddress uintptr
	FirstDnsServerAddress *socketAddress
	DnsSuffix *uint16; Description *uint16; FriendlyName *uint16
	PhysicalAddress [8]byte; PhysicalAddressLength uint32
	Flags uint32; Mtu uint32; IfType uint32; OperStatus uint32
	Ipv6IfIndex uint32; ZoneIndices [16]uint32
	FirstGatewayAddress *socketAddress
}

type socketAddress struct { Sockaddr *windows.RawSockaddrAny; Len int32 }

func winDefaultRouteAndIface() (bool, string, error) {
	var size uint32 = 15 * 1024
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		r0, _, _ := procGetAdaptersAddresses.Call(
			uintptr(windows.AF_UNSPEC),
			uintptr(GAA_FLAG_INCLUDE_GATEWAYS|GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if r0 == uintptr(windows.ERROR_BUFFER_OVERFLOW) { continue }
		if r0 != 0 { return false, "", fmt.Errorf("GetAdaptersAddresses error %d", r0) }
		head := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))
		for aa := head; aa != nil; aa = aa.Next {
			if aa.OperStatus != 1 { continue }
			ifi, _ := net.InterfaceByIndex(int(aa.IfIndex))
			if ifi == nil || (ifi.Flags&net.FlagLoopback) != 0 { continue }
			if aa.FirstGatewayAddress != nil {
				if ifi != nil { return true, ifi.Name, nil }
				return true, "", nil
			}
		}
		return false, "", nil
	}
	return false, "", nil
}

func winHasDNS() bool {
	var size uint32 = 12 * 1024
	buf := make([]byte, size)
	r0, _, _ := procGetAdaptersAddresses.Call(uintptr(windows.AF_UNSPEC), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r0 == uintptr(windows.ERROR_BUFFER_OVERFLOW) { return false }
	if r0 != 0 { return false }
	head := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))
	for aa := head; aa != nil; aa = aa.Next { if aa.FirstDnsServerAddress != nil { return true } }
	return false
}

func winPickUpGlobalInterface() (string, bool) {
	var size uint32 = 16 * 1024
	buf := make([]byte, size)
	r0, _, _ := procGetAdaptersAddresses.Call(uintptr(windows.AF_UNSPEC), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r0 == uintptr(windows.ERROR_BUFFER_OVERFLOW) { return "", false }
	if r0 != 0 { return "", false }
	head := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))
	for aa := head; aa != nil; aa = aa.Next {
		if aa.OperStatus != 1 { continue }
		ifi, _ := net.InterfaceByIndex(int(aa.IfIndex))
		if ifi == nil || (ifi.Flags&net.FlagLoopback) != 0 { continue }
		if ifHasGlobalUnicast(ifi) { return ifi.Name, true }
	}
	return "", false
}

func ifHasGlobalUnicast(ifi *net.Interface) bool {
	addrs, err := ifi.Addrs(); if err != nil { return false }
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) { case *net.IPNet: ip = v.IP; case *net.IPAddr: ip = v.IP }
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() { continue }
		if v4 := ip.To4(); v4 != nil { return true }
		if !ip.IsLinkLocalUnicast() { return true }
	}
	return false
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
