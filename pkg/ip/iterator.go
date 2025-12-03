// Package ip provides IP range iteration utilities
package ip

import (
	"net"
)

// Iterator provides efficient iteration over IP ranges
type Iterator struct {
	ranges     []IPRange
	current    uint32
	rangeIndex int
	totalIPs   uint64
}

// NewIterator creates a new IP range iterator
func NewIterator(ranges []IPRange) *Iterator {
	total := uint64(0)
	for _, r := range ranges {
		total += r.Count()
	}

	iter := &Iterator{
		ranges:     ranges,
		rangeIndex: 0,
		totalIPs:   total,
	}

	if len(ranges) > 0 {
		iter.current = ranges[0].Start
	}

	return iter
}

// TotalIPs returns the total number of IPs in all ranges
func (it *Iterator) TotalIPs() uint64 {
	return it.totalIPs
}

// Next returns the next IP in the iteration
// Returns nil when iteration is complete
func (it *Iterator) Next() net.IP {
	if it.rangeIndex >= len(it.ranges) {
		return nil
	}

	currentRange := &it.ranges[it.rangeIndex]

	// Get current IP
	ip := FromUint32(it.current)

	// Advance to next IP
	if it.current < currentRange.End {
		it.current++
	} else {
		// Move to next range
		it.rangeIndex++
		if it.rangeIndex < len(it.ranges) {
			it.current = it.ranges[it.rangeIndex].Start
		}
	}

	return ip
}

// NextUint32 returns the next IP as uint32 (more efficient)
// Returns 0 and false when iteration is complete
func (it *Iterator) NextUint32() (uint32, bool) {
	if it.rangeIndex >= len(it.ranges) {
		return 0, false
	}

	currentRange := &it.ranges[it.rangeIndex]

	// Get current IP
	ip := it.current

	// Advance to next IP
	if it.current < currentRange.End {
		it.current++
	} else {
		// Move to next range
		it.rangeIndex++
		if it.rangeIndex < len(it.ranges) {
			it.current = it.ranges[it.rangeIndex].Start
		}
	}

	return ip, true
}

// HasNext checks if there are more IPs to iterate
func (it *Iterator) HasNext() bool {
	return it.rangeIndex < len(it.ranges)
}

// Reset resets the iterator to the beginning
func (it *Iterator) Reset() {
	it.rangeIndex = 0
	if len(it.ranges) > 0 {
		it.current = it.ranges[0].Start
	}
}

// Channel returns a channel that yields IPs (useful for concurrent processing)
func (it *Iterator) Channel(bufferSize int) <-chan uint32 {
	ch := make(chan uint32, bufferSize)

	go func() {
		defer close(ch)
		for {
			ip, ok := it.NextUint32()
			if !ok {
				return
			}
			ch <- ip
		}
	}()

	return ch
}
