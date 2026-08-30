package proxy

import (
	"errors"
	"net/http"
	"time"
)

// Limits bounds parser and body work at the local proxy boundary. Zero fields
// select conservative defaults.
type Limits struct {
	MaxHeaderBytes int
	MaxHeaderCount int
	MaxRequestLine int
	// MaxBodyBytes is retained as the compatibility total-body limit. The
	// explicit memory/spool fields are used by request inspection paths.
	MaxBodyBytes         int64
	MaxInMemoryBodyBytes int64
	MaxSpoolBodyBytes    int64
	ReadHeaderTimeout    time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	ConnectTimeout       time.Duration
}

const (
	DefaultMaxHeaderBytes       = 64 << 10
	DefaultMaxHeaderCount       = 100
	DefaultMaxRequestLine       = 8 << 10
	DefaultMaxInMemoryBodyBytes = 8 << 20
	DefaultMaxSpoolBodyBytes    = 64 << 20
	// DefaultMaxBodyBytes names the total request limit used by older
	// callers; it is intentionally the spool limit.
	DefaultMaxBodyBytes = DefaultMaxSpoolBodyBytes
)

func DefaultLimits() Limits {
	return Limits{
		MaxHeaderBytes:       DefaultMaxHeaderBytes,
		MaxHeaderCount:       DefaultMaxHeaderCount,
		MaxRequestLine:       DefaultMaxRequestLine,
		MaxBodyBytes:         DefaultMaxSpoolBodyBytes,
		MaxInMemoryBodyBytes: DefaultMaxInMemoryBodyBytes,
		MaxSpoolBodyBytes:    DefaultMaxSpoolBodyBytes,
		ReadHeaderTimeout:    10 * time.Second,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		IdleTimeout:          60 * time.Second,
		ConnectTimeout:       10 * time.Second,
	}
}

func (l Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = defaults.MaxHeaderBytes
	}
	if l.MaxHeaderCount <= 0 {
		l.MaxHeaderCount = defaults.MaxHeaderCount
	}
	if l.MaxRequestLine <= 0 {
		l.MaxRequestLine = defaults.MaxRequestLine
	}
	if l.MaxSpoolBodyBytes <= 0 {
		if l.MaxBodyBytes > 0 {
			l.MaxSpoolBodyBytes = l.MaxBodyBytes
		} else {
			l.MaxSpoolBodyBytes = defaults.MaxSpoolBodyBytes
		}
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = l.MaxSpoolBodyBytes
	}
	if l.MaxInMemoryBodyBytes <= 0 {
		l.MaxInMemoryBodyBytes = defaults.MaxInMemoryBodyBytes
	}
	if l.MaxInMemoryBodyBytes > l.MaxSpoolBodyBytes {
		l.MaxInMemoryBodyBytes = l.MaxSpoolBodyBytes
	}
	if l.ReadHeaderTimeout <= 0 {
		l.ReadHeaderTimeout = defaults.ReadHeaderTimeout
	}
	if l.ReadTimeout <= 0 {
		l.ReadTimeout = defaults.ReadTimeout
	}
	if l.WriteTimeout <= 0 {
		l.WriteTimeout = defaults.WriteTimeout
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = defaults.IdleTimeout
	}
	if l.ConnectTimeout <= 0 {
		l.ConnectTimeout = defaults.ConnectTimeout
	}
	return l
}

func (l Limits) validateRequest(req *http.Request) error {
	if req == nil {
		return errors.New("proxy request is nil")
	}
	if len(req.RequestURI) > l.MaxRequestLine {
		return errors.New("proxy request line exceeds limit")
	}
	count := 0
	for key, values := range req.Header {
		count += len(values)
		if len(values) == 0 || len(key) > l.MaxHeaderBytes {
			return errors.New("proxy header is invalid")
		}
		for _, value := range values {
			if len(value) > l.MaxHeaderBytes || len(key)+len(value) > l.MaxHeaderBytes {
				return errors.New("proxy header exceeds limit")
			}
		}
	}
	if count > l.MaxHeaderCount {
		return errors.New("proxy header count exceeds limit")
	}
	if req.ContentLength > l.MaxSpoolBodyBytes {
		return errors.New("proxy request body exceeds limit")
	}
	return nil
}
