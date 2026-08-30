//go:build darwin

package runtime

import (
	goruntime "runtime"
	"syscall"
	"unsafe"
)

// withSIGTTOUBlocked makes a foreground ioctl safe when Kordn is temporarily
// in the background. Using the thread mask rather than signal.Ignore keeps
// existing dispositions intact and prevents changes from being inherited by a
// child process.
func withSIGTTOUBlocked(fn func() error) error {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()

	// Darwin's sigset_t is a 32-bit mask. SIGTTOU is signal 22.
	set := uint32(1) << (uint(syscall.SIGTTOU) - 1)
	var old uint32
	if err := darwinSigprocmask(1 /* SIG_BLOCK */, &set, &old); err != nil {
		return err
	}
	result := fn()
	if err := darwinSigprocmask(3 /* SIG_SETMASK */, &old, nil); err != nil && result == nil {
		return err
	}
	return result
}

func darwinSigprocmask(how uintptr, set, old *uint32) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_SIGPROCMASK, how,
		uintptr(unsafe.Pointer(set)), uintptr(unsafe.Pointer(old)))
	if errno != 0 {
		return errno
	}
	return nil
}
