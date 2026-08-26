//go:build darwin || linux

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
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const terminalIOCTLAttempts = 16

// terminalState owns the extra descriptor used by SysProcAttr.Foreground. It
// must remain open until the child has exited and the original process group
// has been put back in the foreground.
type terminalState struct {
	tty          *os.File
	originalPGID int
	restoreOnce  sync.Once
}

// prepareTerminal opts into foreground handoff only when all three effective
// child streams are terminal files. A custom reader/writer or a redirected
// file deliberately selects the isolated Setpgid fallback, even if Kordn
// itself happens to have a controlling terminal. This prevents a command
// whose I/O is captured from unexpectedly receiving terminal signals.
func prepareTerminal(stdin io.Reader, stdout, stderr io.Writer) *terminalState {
	if !usableTerminalStream(stdin, os.Stdin) ||
		!usableTerminalStream(stdout, os.Stdout) ||
		!usableTerminalStream(stderr, os.Stderr) {
		return nil
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	pgid, err := terminalForegroundPGID(int(tty.Fd()))
	if err != nil {
		_ = tty.Close()
		return nil
	}
	if pgid <= 0 || syscall.Getpgrp() != pgid {
		_ = tty.Close()
		return nil
	}
	return &terminalState{tty: tty, originalPGID: pgid}
}

func usableTerminalStream(stream interface{}, fallback *os.File) bool {
	file, ok := stream.(*os.File)
	if stream == nil {
		file = fallback
		ok = file != nil
	}
	if !ok || file == nil {
		return false
	}
	pgid, err := terminalForegroundPGID(int(file.Fd()))
	return err == nil && pgid > 0
}

func (terminal *terminalState) configure(command *exec.Cmd) {
	if terminal == nil {
		return
	}
	// Foreground implies Setpgid. With Pgid left at zero, exec.Cmd's child PID
	// becomes the new process group's ID. Ctty is intentionally a descriptor in
	// the parent: this is not the Setsid/Setctty path.
	command.SysProcAttr = &syscall.SysProcAttr{
		Foreground: true,
		Ctty:       int(terminal.tty.Fd()),
	}
}

// restore returns terminal ownership to the process group that owned it when
// the child was started. It is safe to call more than once. The ioctl is
// bounded and retries interruption, so shutdown cannot wait indefinitely on a
// terminal whose state is already changing.
func (terminal *terminalState) restore() {
	if terminal == nil {
		return
	}
	terminal.restoreOnce.Do(func() {
		defer terminal.tty.Close()
		_ = setTerminalForeground(int(terminal.tty.Fd()), terminal.originalPGID)
	})
}

func terminalForegroundPGID(fd int) (int, error) {
	var pgid int32
	for attempt := 0; attempt < terminalIOCTLAttempts; attempt++ {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGPGRP), uintptr(unsafe.Pointer(&pgid)))
		if errno == 0 {
			return int(pgid), nil
		}
		if errno != syscall.EINTR {
			return 0, errno
		}
	}
	return 0, syscall.EINTR
}

func setTerminalForeground(fd, pgid int) error {
	// TIOCSPGRP from a background process group can generate SIGTTOU. Block
	// only that signal for the duration of this ioctl, preserving the rest of
	// the parent's signal mask and dispositions. The child has already been
	// waited for by every caller of restore.
	return withSIGTTOUBlocked(func() error {
		value := int32(pgid)
		for attempt := 0; attempt < terminalIOCTLAttempts; attempt++ {
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCSPGRP), uintptr(unsafe.Pointer(&value)))
			if errno == 0 {
				return nil
			}
			if errno != syscall.EINTR {
				return errno
			}
		}
		return syscall.EINTR
	})
}
