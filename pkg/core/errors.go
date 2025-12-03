// Package core provides core types and error definitions
package core

import "errors"

var (
	// ErrNoDomain is returned when no domain is specified
	ErrNoDomain = errors.New("domain is required")

	// ErrNoIPRange is returned when no IP range is specified for active scan
	ErrNoIPRange = errors.New("IP range is required for active scan")

	// ErrTooManyWorkers is returned when worker count exceeds limits
	ErrTooManyWorkers = errors.New("worker count exceeds maximum (1000)")

	// ErrInvalidCIDR is returned when CIDR notation is invalid
	ErrInvalidCIDR = errors.New("invalid CIDR notation")

	// ErrInvalidIP is returned when IP address is invalid
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrInvalidConfig is returned when configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
)
