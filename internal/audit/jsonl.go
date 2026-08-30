package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrBackpressure = errors.New("audit queue is full")
var ErrWriterFailed = errors.New("audit writer failed")
var ErrClosed = errors.New("audit writer is closed")

// FsyncMode controls when records are made durable.
type FsyncMode string

const (
	Batch         FsyncMode = "batch"
	Decision      FsyncMode = "decision"
	FsyncBatch              = Batch
	FsyncDecision           = Decision
)

type Options struct {
	QueueCapacity int
	QueueSize     int
	BatchSize     int
	BatchInterval time.Duration
	Fsync         FsyncMode
	FileMode      os.FileMode
	Open          func(string) (*os.File, error)
}

type writerItem struct {
	event   *Event
	barrier chan error
}

type Writer struct {
	file    *os.File
	path    string
	queue   chan writerItem
	options Options
	stop    chan struct{}
	done    chan struct{}
	mu      sync.RWMutex
	failed  error
	closed  bool
	wg      sync.WaitGroup
}

// NewWriter opens a private regular append-only file and starts one writer
// goroutine. The final component is never followed when the platform supports
// O_NOFOLLOW, and an existing symlink or special file is rejected.
func NewWriter(path string, options ...Options) (*Writer, error) {
	var o Options
	if len(options) != 0 {
		o = options[0]
	}
	if o.QueueCapacity <= 0 {
		o.QueueCapacity = o.QueueSize
	}
	if o.QueueCapacity <= 0 {
		o.QueueCapacity = 256
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 32
	}
	if o.BatchInterval <= 0 {
		o.BatchInterval = 100 * time.Millisecond
	}
	if o.Fsync == "" {
		o.Fsync = Batch
	}
	if o.Fsync != Batch && o.Fsync != Decision {
		return nil, errors.New("invalid audit fsync mode")
	}
	if o.FileMode != 0 && o.FileMode.Perm() != 0600 {
		return nil, errors.New("audit file mode must be 0600")
	}
	path = expand(path)
	if path == "" {
		return nil, errors.New("audit path is empty")
	}
	if err := validateParentPath(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, errors.New("create audit directory")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("audit path is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect audit path")
	}
	var f *os.File
	var err error
	if o.Open != nil {
		f, err = o.Open(path)
	} else {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	}
	if err != nil || f == nil {
		return nil, errors.New("open audit file")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("audit path is not a regular file")
	}
	if err := f.Chmod(0600); err != nil {
		return nil, errors.New("protect audit file")
	}
	w := &Writer{file: f, path: path, queue: make(chan writerItem, o.QueueCapacity), options: o, stop: make(chan struct{}), done: make(chan struct{})}
	w.wg.Add(1)
	go w.loop()
	closeOnError = false
	return w, nil
}

func validateParentPath(path string) error {
	// Resolve only the existing directory prefix. System layouts commonly use
	// a harmless symlink such as /var -> /private/var; rejecting that spelling
	// would make a safe audit path platform-dependent. The final file is still
	// opened with O_NOFOLLOW and every existing canonical ancestor is checked.
	path = filepath.Clean(path)
	existing := path
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("inspect audit directory")
		}
		next := filepath.Dir(existing)
		if next == existing {
			return errors.New("audit path has no existing parent")
		}
		existing = next
	}
	canonical, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return errors.New("resolve audit directory")
	}
	for current := filepath.Clean(canonical); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("audit parent is not a private directory")
		}
		// A sticky directory such as /tmp protects entries from other users
		// even though the directory itself is world-writable. The audit path
		// must still have a private existing prefix beneath it.
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("audit parent is group/world-writable")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func expand(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		h, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		if path == "~" {
			return h
		}
		return filepath.Join(h, path[2:])
	}
	return filepath.Clean(path)
}

// Write transfers an independent copy of the event to the bounded queue. It
// never blocks indefinitely and never sends on a channel after Close returns.
func (w *Writer) Write(ctx context.Context, e Event) error {
	if w == nil {
		return ErrWriterFailed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := e.Validate(); err != nil {
		return err
	}
	copy := cloneEvent(e)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return ErrWriterFailed
	}
	if w.closed {
		return ErrClosed
	}
	select {
	case w.queue <- writerItem{event: &copy}:
		return nil
	default:
		return ErrBackpressure
	}
}
func (w *Writer) Enqueue(ctx context.Context, e Event) error { return w.Write(ctx, e) }

func (w *Writer) loop() {
	defer w.wg.Done()
	defer close(w.done)
	ticker := time.NewTicker(w.options.BatchInterval)
	defer ticker.Stop()
	batch := 0
	for {
		select {
		case item := <-w.queue:
			if item.barrier != nil {
				item.barrier <- w.syncResult()
				continue
			}
			if item.event == nil {
				continue
			}
			if err := w.writeOne(*item.event); err != nil {
				w.fail(err)
				return
			}
			batch++
			if w.options.Fsync == Decision && item.event.EventType == RequestDecision {
				if err := w.sync(); err != nil {
					w.fail(err)
					return
				}
				batch = 0
			}
			if batch >= w.options.BatchSize {
				if err := w.sync(); err != nil {
					w.fail(err)
					return
				}
				batch = 0
			}
		case <-ticker.C:
			if batch > 0 {
				if err := w.sync(); err != nil {
					w.fail(err)
					return
				}
				batch = 0
			}
		case <-w.stop:
			if err := w.drain(); err != nil {
				w.fail(err)
			}
			return
		}
	}
}
func (w *Writer) writeOne(e Event) error {
	data, err := e.MarshalJSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := w.file.Write(data)
	if err == nil && n != len(data) {
		return ioErrShortWrite{}
	}
	return err
}

type ioErrShortWrite struct{}

func (ioErrShortWrite) Error() string { return "short audit write" }
func (w *Writer) sync() error         { return w.file.Sync() }
func (w *Writer) syncResult() error {
	if w.Failed() {
		return ErrWriterFailed
	}
	return w.sync()
}
func (w *Writer) drain() error {
	for {
		select {
		case item := <-w.queue:
			if item.barrier != nil {
				item.barrier <- w.syncResult()
				continue
			}
			if item.event != nil {
				if err := w.writeOne(*item.event); err != nil {
					return err
				}
			}
		default:
			return w.sync()
		}
	}
}
func (w *Writer) fail(err error) {
	w.mu.Lock()
	if w.failed == nil {
		w.failed = err
	}
	w.mu.Unlock()
}
func (w *Writer) Failed() bool { return w != nil && w.Failure() != nil }
func (w *Writer) Failure() error {
	if w == nil {
		return ErrWriterFailed
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.failed
}
func (w *Writer) QueueLength() int {
	if w == nil {
		return 0
	}
	return len(w.queue)
}

// Flush is a FIFO barrier: all events accepted before it are written and
// synced before it returns.
func (w *Writer) Flush(ctx context.Context) error {
	if w == nil {
		return ErrWriterFailed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	if w.failed != nil {
		w.mu.Unlock()
		return ErrWriterFailed
	}
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	barrier := make(chan error, 1)
	select {
	case w.queue <- writerItem{barrier: barrier}:
		w.mu.Unlock()
	case <-ctx.Done():
		w.mu.Unlock()
		return ctx.Err()
	}
	select {
	case err := <-barrier:
		if err != nil {
			w.fail(err)
			return ErrWriterFailed
		}
		return nil
	case <-w.done:
		if err := w.Failure(); err != nil {
			return ErrWriterFailed
		}
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	if w.closed {
		err := w.failed
		w.mu.Unlock()
		return err
	}
	w.closed = true
	close(w.stop)
	w.mu.Unlock()
	w.wg.Wait()
	err := w.Failure()
	if closeErr := w.file.Close(); err == nil {
		err = closeErr
	}
	return err
}
func (w *Writer) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

func cloneEvent(e Event) Event {
	out := e
	if e.RootProcess != nil {
		x := *e.RootProcess
		out.RootProcess = &x
	}
	if e.Request != nil {
		x := *e.Request
		out.Request = &x
	}
	if e.Mapping != nil {
		x := *e.Mapping
		out.Mapping = &x
	}
	if e.Decision != nil {
		x := *e.Decision
		if e.Decision.MatchedRuleIDs != nil {
			x.MatchedRuleIDs = append([]string{}, e.Decision.MatchedRuleIDs...)
		}
		out.Decision = &x
	}
	if e.Upstream != nil {
		x := *e.Upstream
		out.Upstream = &x
	}
	if e.Timing != nil {
		x := *e.Timing
		out.Timing = &x
	}
	if e.Metrics != nil {
		x := *e.Metrics
		x.Counters = make(map[string]uint64, len(e.Metrics.Counters))
		for k, v := range e.Metrics.Counters {
			x.Counters[k] = v
		}
		x.Histograms = make(map[string]Histogram, len(e.Metrics.Histograms))
		for k, v := range e.Metrics.Histograms {
			x.Histograms[k] = v
		}
		out.Metrics = &x
	}
	out.IAMRequirements = append([]Requirement(nil), e.IAMRequirements...)
	for i := range out.IAMRequirements {
		out.IAMRequirements[i].Resources = append([]string(nil), e.IAMRequirements[i].Resources...)
	}
	return out
}

func ReadEvents(path string) ([]Event, error) {
	path = expand(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("audit path is not a regular file")
	}
	const maxAuditRead = 256 << 20
	if info.Size() > maxAuditRead {
		return nil, errors.New("audit file is too large to query")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("audit file contains a partial final record")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > 1000000 {
		return nil, errors.New("audit file contains too many events")
	}
	out := make([]Event, 0, len(lines))
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
