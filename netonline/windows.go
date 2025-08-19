//go:build windows
// +build windows

package netonline

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

type handle = uintptr

var (
	iphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = iphlpapi.NewProc("NotifyIpInterfaceChange")
	procNotifyRouteChange2      = iphlpapi.NewProc("NotifyRouteChange2")
	procCancelMibChangeNotify2  = iphlpapi.NewProc("CancelMibChangeNotify2")
	procGetAdaptersAddresses    = iphlpapi.NewProc("GetAdaptersAddresses")
	procGetBestInterfaceEx      = iphlpapi.NewProc("GetBestInterfaceEx")
)

const (
	AF_UNSPEC = 0
	AF_INET   = 2
	AF_INET6  = 23

	GAA_FLAG_SKIP_ANYCAST     = 0x2
	GAA_FLAG_SKIP_MULTICAST   = 0x4
	GAA_FLAG_INCLUDE_GATEWAYS = 0x80
)

// Subset of IP_ADAPTER_ADDRESSES with fields we actually read.
// Layout matches Windows SDK alignment for these members.
type ipAdapterAddresses struct {
	Length                uint32
	IfIndex               uint32
	Next                  *ipAdapterAddresses
	AdapterName           *byte
	FirstUnicastAddress   uintptr
	FirstAnycastAddress   uintptr
	FirstMulticastAddress uintptr
	FirstDnsServerAddress *socketAddress
	DnsSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	Mtu                   uint32
	IfType                uint32
	OperStatus            uint32
	Ipv6IfIndex           uint32
	ZoneIndices           [16]uint32
	FirstGatewayAddress   *socketAddress
}

type socketAddress struct {
	Sockaddr *windows.RawSockaddrAny
	Len      int32
}

// sockaddr_in for GetBestInterfaceEx (IPv4)
type sockaddrIn struct {
	Family uint16 // AF_INET
	Port   uint16
	Addr   [4]byte // network byte order
	Zero   [8]byte
}

// sockaddr_in6 for GetBestInterfaceEx (IPv6)
type sockaddrIn6 struct {
	Family   uint16 // AF_INET6
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeId  uint32
}

func startOSEventStream(ctx context.Context) (<-chan osEvent, <-chan error) {
	out := make(chan osEvent, 8)
	errc := make(chan error, 1)

	var stopped uint32 // 0 = running, 1 = stopping/stopped

	go func() {
		defer close(out)
		defer close(errc)

		var hIf, hRt handle

		send := func(reason string) {
			if atomic.LoadUint32(&stopped) == 1 {
				return
			}
			select {
			case out <- osEvent{reason: reason}:
			default:
			}
		}

		// Interface changes
		ifcb := windows.NewCallback(func(callerCtx uintptr, row uintptr, notificationType uint32) uintptr {
			send("ip interface change")
			return 0 // NO_ERROR
		})
		r1, _, e1 := procNotifyIpInterfaceChange.Call(
			uintptr(AF_UNSPEC), ifcb, 0, uintptr(1), uintptr(unsafe.Pointer(&hIf)),
		)
		if r1 != 0 {
			errc <- fmt.Errorf("NotifyIpInterfaceChange failed: %v", e1)
			return
		}

		// Route changes
		rtcb := windows.NewCallback(func(callerCtx uintptr, row uintptr, notificationType uint32) uintptr {
			send("route change")
			return 0 // NO_ERROR
		})
		r2, _, e2 := procNotifyRouteChange2.Call(
			uintptr(AF_UNSPEC), rtcb, 0, uintptr(1), uintptr(unsafe.Pointer(&hRt)),
		)
		if r2 != 0 {
			// Cleanup the first subscription before exiting
			_, _, _ = procCancelMibChangeNotify2.Call(uintptr(hIf))
			errc <- fmt.Errorf("NotifyRouteChange2 failed: %v", e2)
			return
		}

		// Wait for cancellation, then tear down subscriptions *before* returning,
		// so callbacks can no longer enqueue events.
		<-ctx.Done()
		atomic.StoreUint32(&stopped, 1)
		_, _, _ = procCancelMibChangeNotify2.Call(uintptr(hRt))
		_, _, _ = procCancelMibChangeNotify2.Call(uintptr(hIf))
	}()

	return out, errc
}

func recomputeOnline() (bool, string, error) {
	// Primary path: gateway from GAAs (works on many NICs)
	hasDef, ifn, err := winDefaultRouteAndIface()
	if err != nil {
		return false, "default route check failed", err
	}

	// Fallback path: if gateway not surfaced by GAAs, ask the routing engine
	if !hasDef || ifn == "" {
		ifn2, ok := winDefaultRouteViaBestInterface()
		if ok {
			ifn = ifn2
			hasDef = true
		}
	}

	if hasDef && ifn != "" {
		ifi, err := net.InterfaceByName(ifn)
		if err != nil || (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			return false, "default iface down/loopback", nil
		}
		if !ifaceHasUsableAddr(ifn) {
			return false, "default iface has no usable IP", nil
		}
		if !winHasDNS() {
			return false, "no DNS resolver", nil
		}
		return true, "default via " + ifn, nil
	}

	// Last resort: operational interface with global unicast (covers ICS/bridge, some VPNs)
	alt, ok := winPickUpGlobalInterface()
	if !ok {
		return false, "no default route", nil
	}
	if !winHasDNS() {
		return false, "no DNS resolver", nil
	}
	return true, "fallback: up iface " + alt, nil
}

// -------------------- Default route detection helpers --------------------

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
		if r0 == uintptr(windows.ERROR_BUFFER_OVERFLOW) {
			continue // grow/retry
		}
		if r0 != 0 {
			return false, "", fmt.Errorf("GetAdaptersAddresses error %d", r0)
		}
		head := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))
		for aa := head; aa != nil; aa = aa.Next {
			if aa.OperStatus != 1 { // IfOperStatusUp
				continue
			}
			ifi, _ := net.InterfaceByIndex(int(aa.IfIndex))
			if ifi == nil || (ifi.Flags&net.FlagLoopback) != 0 {
				continue
			}
			if aa.FirstGatewayAddress != nil {
				if ifi != nil {
					return true, ifi.Name, nil
				}
				return true, "", nil
			}
		}
		return false, "", nil
	}
	return false, "", nil
}

// Route-engine fallback: ask Windows which interface it would use to reach well-known destinations.
// Try IPv6 first (in case of v6-only), then IPv4.
func winDefaultRouteViaBestInterface() (string, bool) {
	// v6 target: 2606:4700:4700::1111 (Cloudflare)
	var sa6 sockaddrIn6
	sa6.Family = AF_INET6
	sa6.Addr = [16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11}
	if ifn, ok := winBestInterfaceName((*windows.RawSockaddrAny)(unsafe.Pointer(&sa6))); ok {
		return ifn, true
	}

	// v4 target: 1.1.1.1
	var sa4 sockaddrIn
	sa4.Family = AF_INET
	sa4.Addr = [4]byte{1, 1, 1, 1}
	if ifn, ok := winBestInterfaceName((*windows.RawSockaddrAny)(unsafe.Pointer(&sa4))); ok {
		return ifn, true
	}
	return "", false
}

func winBestInterfaceName(dst *windows.RawSockaddrAny) (string, bool) {
	var idx uint32
	r0, _, _ := procGetBestInterfaceEx.Call(
		uintptr(unsafe.Pointer(dst)),
		uintptr(unsafe.Pointer(&idx)),
	)
	if r0 != 0 || idx == 0 {
		return "", false
	}
	ifi, err := net.InterfaceByIndex(int(idx))
	if err != nil || ifi == nil || (ifi.Flags&net.FlagLoopback) != 0 {
		return "", false
	}
	return ifi.Name, true
}

// -------------------- DNS / Interface helpers --------------------

func winHasDNS() bool {
	var size uint32 = 12 * 1024
	buf := make([]byte, size)
	r0, _, _ := procGetAdaptersAddresses.Call(
		uintptr(windows.AF_UNSPEC),
		0, // include DNS info
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r0 == uintptr(windows.ERROR_BUFFER_OVERFLOW) {
		return false
	}
	if r0 != 0 {
		return false
	}
	head := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))
	for aa := head; aa != nil; aa = aa.Next {
		if aa.FirstDnsServerAddress != nil {
			return true
		}
	}
	return false
}

func winPickUpGlobalInterface() (string, bool) {
	var size uint32 = 16 * 1024
	buf := make([]byte, size)
	r0, _, _ := procGetAdaptersAddresses.Call(
		uintptr(windows.AF_UNSPEC),
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r0 == uintptr(windows.ERROR_BUFFER_OVERFLOW) {
		return "", false
	}
	if r0 != 0 {
		return "", false
	}
	head := (*ipAdapterAddresses)(unsafe.Pointer(&buf[0]))
	for aa := head; aa != nil; aa = aa.Next {
		if aa.OperStatus != 1 {
			continue
		}
		ifi, _ := net.InterfaceByIndex(int(aa.IfIndex))
		if ifi == nil || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		if ifHasGlobalUnicast(ifi) {
			return ifi.Name, true
		}
	}
	return "", false
}

func ifHasGlobalUnicast(ifi *net.Interface) bool {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return true
		}
		// IPv6: accept non-link-local as "global" enough for our passive gate.
		if !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func ifaceHasUsableAddr(ifname string) bool {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			if !v4.IsUnspecified() {
				return true
			}
			continue
		}
		if ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return true
	}
	return false
}
