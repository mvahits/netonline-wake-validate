
package netonline

import (
	"context"
	"time"
)

// StartWakeGapWatcher emits a signal after resume from sleep/hibernate.
// It checks for a large jump in the monotonic clock, which is cross-platform.
func StartWakeGapWatcher(ctx context.Context, sample, gapThreshold time.Duration) <-chan struct{} {
	if sample <= 0 { sample = time.Second }
	if gapThreshold <= 0 { gapThreshold = 1500 * time.Millisecond }
	out := make(chan struct{}, 1)
	t := time.NewTicker(sample)
	last := time.Now()
	go func() {
		defer close(out); defer t.Stop()
		for {
			select {
			case <-ctx.Done(): return
			case now := <-t.C:
				d := now.Sub(last); last = now
				if d >= sample + gapThreshold {
					select { case out <- struct{}{}: default: }
				}
			}
		}
	}()
	return out
}
