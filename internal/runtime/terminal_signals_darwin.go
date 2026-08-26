//go:build darwin

// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
