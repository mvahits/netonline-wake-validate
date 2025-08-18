
//go:build darwin || freebsd
// +build darwin freebsd

package netonline

import (
	"bufio"
	"os"
	"strings"
)

func hasDNSResolver() bool {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil { return false }
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[1] != "" { return true }
		}
	}
	return false
}
