package netonline

import (
	"context"
	"time"
)

type Event struct {
	Online    bool
	ChangedAt time.Time
	Cause     string
}

type osEvent struct{ reason string }

func Watch(ctx context.Context) (<-chan Event, <-chan error) {
	out := make(chan Event, 1)
	errc := make(chan error, 1)
	events, errs := startOSEventStream(ctx)

	online, why, err := recomputeOnline()
	if err != nil {
		errc <- err
	}
	last := online
	out <- Event{Online: online, ChangedAt: time.Now(), Cause: "initial: " + why}

	go func() {
		defer close(out)
		defer close(errc)
		var lastReason string
		var debounceTimer *time.Timer
		trigger := func() {
			online, why, err := recomputeOnline()
			if err != nil {
				errc <- err
				return
			}
			if online != last {
				last = online
				cause := why
				if lastReason != "" {
					cause = lastReason + "; " + why
				}
				out <- Event{Online: online, ChangedAt: time.Now(), Cause: cause}
			}
		}
		for {
			select {
			case <-ctx.Done():
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				return
			case e := <-events:
				lastReason = e.reason
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(750*time.Millisecond, trigger)
			case err := <-errs:
				if err != nil {
					errc <- err
				}
			}
		}
	}()
	return out, errc
}
