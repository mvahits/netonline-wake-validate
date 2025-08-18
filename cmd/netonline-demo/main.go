package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/netonline/netonline"
)

func main() {
	validate := flag.Bool("validate", true, "run active probes when online=true events arrive")
	timeout := flag.Duration("timeout", 5*time.Second, "overall probe timeout")
	require := flag.Int("require", 3, "probe quorum required to accept connectivity (>=2 recommended)")
	wakeSample := flag.Duration("wake-sample", time.Second, "wake detector sampling period")
	wakeGap := flag.Duration("wake-gap", 1500*time.Millisecond, "gap threshold to classify as wake")
	flag.Parse()
	fmt.Printf("validate=%v, timeout=%s, require=%d, wake-sample=%s, wake-gap=%s\n", *validate, timeout, require, wakeSample, wakeGap)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	events, errs := netonline.Watch(ctx)
	wakes := netonline.StartWakeGapWatcher(ctx, *wakeSample, *wakeGap)

	logEvent := func(ts time.Time, online bool, cause string, validated *bool, why string) {
		if validated == nil {
			fmt.Printf("[%s] online=%v cause=%s\n", ts.Format("2006-01-02T15:04:05Z07:00"), online, cause)
			return
		}
		fmt.Printf("[%s] online=%v cause=%s connectivity=%v (%s)\n", ts.Format("2006-01-02T15:04:05Z07:00"), online, cause, *validated, why)
	}

	for {
		select {
		case ev := <-events:
			if ev.Online && *validate {
				ok, why := connectivityCheck(ctx, *timeout, *require)
				logEvent(ev.ChangedAt, ev.Online, ev.Cause, &ok, why)
			} else {
				logEvent(ev.ChangedAt, ev.Online, ev.Cause, nil, "")
			}
		case <-wakes:
			online, cause, _ := netonline.Evaluate()
			ts := time.Now()
			if online && *validate {
				ok, why := connectivityCheck(ctx, *timeout, *require)
				logEvent(ts, online, "wake; "+cause, &ok, why)
			} else {
				logEvent(ts, online, "wake; "+cause, nil, "")
			}
		case err := <-errs:
			if err != nil {
				fmt.Println("error:", err)
			}
		}
	}
}

func connectivityCheck(parent context.Context, timeout time.Duration, require int) (bool, string) {
	if require <= 0 {
		require = 1
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type probe struct {
		name string
		fn   func(context.Context) error
	}
	probes := []probe{
		{name: "dns:example.com", fn: probeDNS("example.com")},
		{name: "dns:one.one.one.one", fn: probeDNS("one.one.one.one")},
		{name: "tcp:1.1.1.1:443", fn: probeTCP("1.1.1.1:443")},
		{name: "tcp:8.8.8.8:443", fn: probeTCP("8.8.8.8:443")},
		{name: "http:gstatic204", fn: probeHTTP204("http://connectivitycheck.gstatic.com/generate_204")},
		{name: "http:clients3.google", fn: probeHTTP204("http://clients3.google.com/generate_204")},
	}
	res := make(chan error, len(probes))
	for _, p := range probes {
		p := p
		go func() { res <- p.fn(ctx) }()
	}
	ok := 0
	for i := 0; i < len(probes); i++ {
		select {

		case <-ctx.Done():
			if ok >= require {
				return true, "ok (timeout after quorum)"
			}
			return false, "timeout"
		case err := <-res:
			if err == nil {
				ok++
				if ok >= require {
					return true, "ok"
				}
			}
		}
	}
	if ok >= require {
		return true, "ok"
	}
	return false, "insufficient successes"
}

func probeDNS(host string) func(context.Context) error {
	return func(ctx context.Context) error {
		var r net.Resolver
		_, err := r.LookupHost(ctx, host)
		return err
	}
}
func probeTCP(addr string) func(context.Context) error {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: 1200 * time.Millisecond}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		_ = c.Close()
		return nil
	}
}
func probeHTTP204(url string) func(context.Context) error {
	return func(ctx context.Context) error {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		cl := &http.Client{Transport: tr, Timeout: 1500 * time.Millisecond}
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		fmt.Print("HTTP response status: ", resp.Status)
		if resp.StatusCode == http.StatusNoContent {
			return nil
		}
		return errors.New("non-204")
	}
}
