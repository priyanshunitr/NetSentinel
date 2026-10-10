package store

// ring retains values, not pointers to mutable caller-owned records.
type ring[T any] struct {
	values      []T
	next, count int
}

func newRing[T any](capacity int) ring[T] { return ring[T]{values: make([]T, capacity)} }

func (r *ring[T]) add(value T) {
	r.values[r.next] = value
	r.next = (r.next + 1) % len(r.values)
	if r.count < len(r.values) {
		r.count++
	}
}

func (r *ring[T]) recent(limit int, match func(T) bool) []T {
	result := make([]T, 0, min(limit, r.count))
	for offset := 0; offset < r.count && len(result) < limit; offset++ {
		value := r.values[(r.next-1-offset+len(r.values))%len(r.values)]
		if match == nil || match(value) {
			result = append(result, value)
		}
	}
	return result
}
