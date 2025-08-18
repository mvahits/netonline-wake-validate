
//go:build linux
// +build linux

package netonline

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func hasDNSResolver() bool {
	paths := []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil { continue }
		sc := bufio.NewScanner(f)
		found := false
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "nameserver") { continue }
			parts := strings.Fields(line)
			if len(parts) < 2 { continue }
			addr := net.ParseIP(parts[1])
			if addr == nil || addr.IsLoopback() { continue }
			found = true; break
		}
		f.Close()
		if found { return true }
	}
	return false
}
