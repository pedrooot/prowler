package service

import (
	"context"
	"sync"
)

// DefaultConcurrency bounds the per-service API fan-out when the caller does
// not set one.
const DefaultConcurrency = 8

// ForEach runs fn over items with at most limit in flight, which is how a
// service enriches the resources it listed without opening one connection
// per resource.
//
// fn is responsible for its own locking; the resources it mutates are the
// items themselves, so a per-item write needs none.
func ForEach[T any](ctx context.Context, limit int, items []T, fn func(context.Context, T)) {
	if limit <= 0 {
		limit = DefaultConcurrency
	}
	if len(items) < limit {
		limit = len(items)
	}
	if limit == 0 {
		return
	}

	work := make(chan T)
	var wg sync.WaitGroup
	wg.Add(limit)
	for range limit {
		go func() {
			defer wg.Done()
			for item := range work {
				if ctx.Err() != nil {
					return
				}
				fn(ctx, item)
			}
		}()
	}

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		work <- item
	}
	close(work)
	wg.Wait()
}
