package sigv4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// BodyOptions bounds a captured request body. The defaults are eight MiB of
// memory and 64 MiB total private spool storage.
type BodyOptions struct {
	MaxInMemoryBytes int64
	MaxSpoolBytes    int64
	TempDir          string
}

func DefaultBodyOptions() BodyOptions {
	return BodyOptions{MaxInMemoryBytes: defaultBodyMemory, MaxSpoolBytes: defaultBodySpool}
}

// Body is a reusable, seekable request payload. A body is either held in
// memory or in an O_EXCL-created 0600 file. Its file is removed on Close.
type Body struct {
	mu        sync.Mutex
	memory    []byte
	path      string
	size      int64
	hash      [sha256.Size]byte
	readers   map[*fileReader]struct{}
	closed    bool
	closeErr  error
	closeDone chan struct{}
}

// NewBody captures reader into the bounded body abstraction. It is useful for
// callers outside the HTTP verifier and never returns a partially usable body.
func NewBody(reader io.Reader, options BodyOptions) (*Body, error) {
	if reader == nil {
		reader = http.NoBody
	}
	if options.MaxInMemoryBytes < 0 || options.MaxSpoolBytes < 0 {
		return nil, newError(CodeMalformedRequest, "body limits are invalid")
	}
	options = normalizedBodyOptions(options)
	if options.MaxInMemoryBytes <= 0 || options.MaxSpoolBytes <= 0 || options.MaxInMemoryBytes > options.MaxSpoolBytes {
		return nil, newError(CodeMalformedRequest, "body limits are invalid")
	}
	result := &Body{}
	hasher := sha256.New()
	var spool *os.File
	cleanup := func() {
		if spool != nil {
			_ = spool.Close()
		}
		if result.path != "" {
			_ = os.Remove(result.path)
		}
		for i := range result.memory {
			result.memory[i] = 0
		}
		result.memory = nil
	}
	defer func() {
		if spool != nil {
			_ = spool.Close()
		}
	}()

	buffer := make([]byte, 32*1024)
	noProgress := 0
	for {
		remaining := options.MaxSpoolBytes - result.size
		if remaining < 0 {
			cleanup()
			return nil, newError(CodeOversizedBody, "request body exceeds limit")
		}
		if remaining == 0 {
			// One byte beyond the limit is enough to distinguish an exactly
			// bounded body from an oversized one.
			buffer = buffer[:1]
		} else if int64(len(buffer)) > remaining {
			buffer = buffer[:remaining]
		}
		n, err := reader.Read(buffer)
		if n < 0 || n > len(buffer) {
			cleanup()
			return nil, newError(CodeBodyReadFailure, "request body read failed")
		}
		if n > 0 {
			if result.size+int64(n) > options.MaxSpoolBytes {
				cleanup()
				return nil, newError(CodeOversizedBody, "request body exceeds limit")
			}
			if _, writeErr := hasher.Write(buffer[:n]); writeErr != nil {
				cleanup()
				return nil, newError(CodeBodyReadFailure, "request body read failed")
			}
			if spool == nil && result.size+int64(n) <= options.MaxInMemoryBytes {
				result.memory = appendBounded(result.memory, buffer[:n], options.MaxInMemoryBytes)
			} else {
				if spool == nil {
					var createErr error
					spool, createErr = os.CreateTemp(options.TempDir, "kordn-sigv4-")
					if createErr != nil {
						cleanup()
						return nil, newError(CodeBodyReadFailure, "private body spool is unavailable")
					}
					result.path = filepath.Clean(spool.Name())
					if chmodErr := spool.Chmod(0o600); chmodErr != nil {
						cleanup()
						return nil, newError(CodeBodyReadFailure, "private body spool permissions are unavailable")
					}
					if len(result.memory) != 0 {
						if _, writeErr := spool.Write(result.memory); writeErr != nil {
							cleanup()
							return nil, newError(CodeBodyReadFailure, "private body spool write failed")
						}
						for i := range result.memory {
							result.memory[i] = 0
						}
						result.memory = nil
					}
					// The descriptor remains private even if a caller changes the
					// process umask between capture and a later write.
					if info, statErr := spool.Stat(); statErr != nil || info.Mode().Perm() != 0o600 {
						cleanup()
						return nil, newError(CodeBodyReadFailure, "private body spool permissions are unavailable")
					}
					_ = spool.Sync()
					if _, writeErr := spool.Write(buffer[:n]); writeErr != nil {
						cleanup()
						return nil, newError(CodeBodyReadFailure, "private body spool write failed")
					}
				} else if _, writeErr := spool.Write(buffer[:n]); writeErr != nil {
					cleanup()
					return nil, newError(CodeBodyReadFailure, "private body spool write failed")
				}
			}
			result.size += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			cleanup()
			return nil, newError(CodeBodyReadFailure, "request body read failed")
		}
		if n == 0 {
			// A reader is permitted to return (0, nil), but an unbounded
			// sequence would otherwise consume a verifier goroutine forever.
			noProgress++
			if noProgress >= 100 {
				cleanup()
				return nil, newError(CodeBodyReadFailure, "request body read failed")
			}
			continue
		}
		noProgress = 0
	}
	copy(result.hash[:], hasher.Sum(nil))
	if spool != nil {
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			cleanup()
			return nil, newError(CodeBodyReadFailure, "private body spool is unavailable")
		}
	}
	return result, nil
}

func appendBounded(dst, src []byte, max int64) []byte {
	needed := len(dst) + len(src)
	if needed <= cap(dst) {
		return append(dst, src...)
	}
	maxInt := int64(int(^uint(0) >> 1))
	if max > maxInt {
		max = maxInt
	}
	nextCapacity := cap(dst) * 2
	if nextCapacity < needed {
		nextCapacity = needed
	}
	if int64(nextCapacity) > max {
		nextCapacity = int(max)
	}
	if nextCapacity < needed {
		// The caller has already checked the body bound. Retain the exact
		// required capacity if growth arithmetic wrapped on an unusual limit.
		nextCapacity = needed
	}
	next := make([]byte, len(dst), nextCapacity)
	copy(next, dst)
	return append(next, src...)
}

func normalizedBodyOptions(options BodyOptions) BodyOptions {
	defaults := DefaultBodyOptions()
	if options.MaxInMemoryBytes <= 0 {
		options.MaxInMemoryBytes = defaults.MaxInMemoryBytes
	}
	if options.MaxSpoolBytes <= 0 {
		options.MaxSpoolBytes = defaults.MaxSpoolBytes
	}
	return options
}

// ReadBody is an alias for NewBody with a name matching the request-boundary
// operation in the proxy.
func ReadBody(reader io.Reader, options BodyOptions) (*Body, error) {
	return NewBody(reader, options)
}

// CaptureRequestBody drains req.Body exactly once, replaces it with a
// reusable reader, and records the Body in the request context for Resign.
func CaptureRequestBody(req *http.Request, options BodyOptions) (*Body, error) {
	if req == nil {
		return nil, newError(CodeMalformedRequest, "request is unavailable")
	}
	if existing := bodyFromRequest(req); existing != nil {
		// Repeated inspection must start from offset zero without retaining an
		// older file descriptor. The Body remains shared, but each request
		// reader is an independent view of it.
		if req.Body != nil && req.Body != http.NoBody {
			_ = req.Body.Close()
			req.Body = http.NoBody
		}
		reader, err := existing.Reader()
		if err != nil {
			return nil, newError(CodeBodyReadFailure, "request body is unavailable")
		}
		if closer, ok := reader.(io.Closer); ok {
			_ = closer.Close()
		}
		req.Body = existing.newReader()
		req.GetBody = func() (io.ReadCloser, error) { return existing.newReader(), nil }
		return existing, nil
	}
	if options.MaxInMemoryBytes < 0 || options.MaxSpoolBytes < 0 {
		return nil, newError(CodeMalformedRequest, "body limits are invalid")
	}
	options = normalizedBodyOptions(options)
	originalContentLength := req.ContentLength
	if req.ContentLength > options.MaxSpoolBytes {
		if req.Body != nil && req.Body != http.NoBody {
			_ = req.Body.Close()
			req.Body = http.NoBody
		}
		return nil, newError(CodeOversizedBody, "request body exceeds limit")
	}
	reader := io.Reader(http.NoBody)
	if req.Body != nil && req.Body != http.NoBody {
		reader = req.Body
	}
	body, err := NewBody(reader, options)
	if req.Body != nil && req.Body != http.NoBody {
		_ = req.Body.Close()
		req.Body = http.NoBody
	}
	if err != nil {
		return nil, err
	}
	setRequestBody(req, body)
	// A chunked/unknown-length request must not gain a synthetic signed
	// Content-Length merely because inspection buffered it. Resigning sets a
	// length on its private clone later.
	if originalContentLength < 0 {
		req.ContentLength = -1
	}
	return body, nil
}

func setRequestBody(req *http.Request, body *Body) {
	if req == nil || body == nil {
		return
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return body.newReader(), nil
	}
	req.ContentLength = body.size
	// WithContext returns a shallow copy. Copy it back so the reusable body
	// marker remains attached to the caller-owned request.
	*req = *req.WithContext(contextWithBody(req.Context(), body))
	req.Body = body.newReader()
}

type bodyContextKey struct{}

type bodyContext struct{ body *Body }

func contextWithBody(ctx context.Context, body *Body) context.Context {
	return context.WithValue(ctx, bodyContextKey{}, bodyContext{body: body})
}

func bodyFromRequest(req *http.Request) *Body {
	if req == nil {
		return nil
	}
	if value, ok := req.Context().Value(bodyContextKey{}).(bodyContext); ok {
		return value.body
	}
	return nil
}

// BodyFromRequest returns the reusable body associated with a captured
// request, if any.
func BodyFromRequest(req *http.Request) *Body { return bodyFromRequest(req) }

// CloseBody removes a captured body spool. It is safe to call on every path,
// including after a failed verification or failed upstream round trip.
func CloseBody(req *http.Request) error {
	if body := bodyFromRequest(req); body != nil {
		return body.Close()
	}
	return nil
}

// closeRequestBody releases both the request's current reader and any
// captured body. The two closes are intentionally independent: a request
// reader owns only its descriptor, while Body owns the spool and all readers.
// Both operations are idempotent, so callers can use this helper from an
// early-rejection path and the verifier's deferred cleanup can still run.
func closeRequestBody(req *http.Request) {
	if req == nil {
		return
	}
	if req.Body != nil && req.Body != http.NoBody {
		_ = req.Body.Close()
		// Mark the request reader closed so a deferred cleanup cannot invoke a
		// caller-owned Close method a second time.
		req.Body = http.NoBody
	}
	_ = CloseBody(req)
}

func (b *Body) newReader() io.ReadCloser {
	reader, err := b.Reader()
	if err != nil {
		return &bodyErrorReader{err: err}
	}
	wrapped := &bodyReader{ReadSeeker: reader}
	if closer, ok := reader.(io.Closer); ok {
		wrapped.closer = closer
	}
	return wrapped
}

type bodyErrorReader struct{ err error }

func (r *bodyErrorReader) Read([]byte) (int, error) { return 0, r.err }
func (r *bodyErrorReader) Close() error             { return nil }

type bodyReader struct {
	io.ReadSeeker
	closer io.Closer
}

// Close releases only this reader. Body is shared by verification, signing,
// and the request's GetBody callback, so closing one view must not invalidate
// the other views. The request pipeline owns the final Body.Close call.
func (r *bodyReader) Close() error {
	if r == nil || r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

// Reader returns a fresh seekable reader at offset zero. File-backed readers
// use a fresh descriptor, avoiding races between verification and signing.
func (b *Body) Reader() (io.ReadSeeker, error) {
	if b == nil {
		return nil, errors.New("body is unavailable")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("body is closed")
	}
	if b.path != "" {
		file, err := os.Open(b.path)
		if err != nil {
			return nil, err
		}
		reader := &fileReader{File: file, body: b}
		if b.readers == nil {
			b.readers = make(map[*fileReader]struct{})
		}
		b.readers[reader] = struct{}{}
		return reader, nil
	}
	return &bytesReader{data: b.memory, owner: b}, nil
}

type bytesReader struct {
	data  []byte
	off   int
	owner *Body
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.owner != nil {
		r.owner.mu.Lock()
		defer r.owner.mu.Unlock()
		if r.owner.closed {
			return 0, errors.New("body is closed")
		}
	}
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func (r *bytesReader) Seek(offset int64, whence int) (int64, error) {
	if r.owner != nil {
		r.owner.mu.Lock()
		defer r.owner.mu.Unlock()
		if r.owner.closed {
			return 0, errors.New("body is closed")
		}
	}
	position := int64(r.off)
	switch whence {
	case io.SeekStart:
		position = offset
	case io.SeekCurrent:
		position += offset
	case io.SeekEnd:
		position = int64(len(r.data)) + offset
	default:
		return 0, errors.New("body seek mode is invalid")
	}
	if position < 0 || position > int64(len(r.data)) {
		return 0, errors.New("body seek offset is invalid")
	}
	r.off = int(position)
	return position, nil
}

type fileReader struct {
	*os.File
	body *Body
	once sync.Once
	err  error
}

func (r *fileReader) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.err = r.File.Close()
		if r.body != nil {
			r.body.mu.Lock()
			delete(r.body.readers, r)
			r.body.mu.Unlock()
		}
	})
	return r.err
}

func (b *Body) Size() int64 {
	if b == nil {
		return 0
	}
	return b.size
}

func (b *Body) SHA256() string {
	if b == nil {
		return ""
	}
	return hex.EncodeToString(b.hash[:])
}

func (b *Body) SpoolPath() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.path
}

func (b *Body) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		done := b.closeDone
		b.mu.Unlock()
		if done != nil {
			<-done
		}
		b.mu.Lock()
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	b.closed = true
	b.closeDone = make(chan struct{})
	done := b.closeDone
	readers := make([]*fileReader, 0, len(b.readers))
	for reader := range b.readers {
		readers = append(readers, reader)
	}
	b.readers = nil
	path := b.path
	memory := b.memory
	b.memory = nil
	b.mu.Unlock()

	// Do not hold b.mu while closing a fileReader: its Close method removes
	// itself from the body's reader set and must be able to take that lock.
	var firstErr error
	for _, reader := range readers {
		if err := reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if path != "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	for i := range memory {
		memory[i] = 0
	}
	b.mu.Lock()
	b.closeErr = firstErr
	close(done)
	b.mu.Unlock()
	return firstErr
}
