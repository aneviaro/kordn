//go:build linux

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

	// Linux's rt_sigprocmask accepts the kernel sigset size (not the Go
	// userspace representation size). SIGTTOU is signal 22 on Linux.
	// Most Linux architectures use a 64-bit kernel mask; the MIPS variants
	// use 128 bits.
	var set, old [2]uint64
	set[0] = 1 << (uint(syscall.SIGTTOU) - 1)
	sigsetSize := uintptr(8)
	switch goruntime.GOARCH {
	case "mips", "mipsle", "mips64", "mips64le":
		sigsetSize = 16
	}
	if err := linuxSigprocmask(0 /* SIG_BLOCK */, &set, &old, sigsetSize); err != nil {
		return err
	}
	result := fn()
	if err := linuxSigprocmask(2 /* SIG_SETMASK */, &old, nil, sigsetSize); err != nil && result == nil {
		return err
	}
	return result
}

func linuxSigprocmask(how uintptr, set, old *[2]uint64, sigsetSize uintptr) error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, how,
		uintptr(unsafe.Pointer(set)), uintptr(unsafe.Pointer(old)), sigsetSize, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
