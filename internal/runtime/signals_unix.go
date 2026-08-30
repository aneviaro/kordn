//go:build darwin || linux

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func configureProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func newSignalForwarder() (chan os.Signal, func()) {
	channel := make(chan os.Signal, 16)
	signal.Notify(channel, os.Interrupt, syscall.SIGTERM, syscall.SIGWINCH)
	// Do not close the channel: a signal delivery racing with shutdown must
	// never panic by sending to a closed channel. signal.Stop is sufficient to
	// release the notifier and the channel is collected with the supervisor.
	return channel, func() { signal.Stop(channel) }
}

func forwardToProcessGroup(pid int, sig os.Signal) error {
	value, ok := sig.(syscall.Signal)
	if !ok {
		return errors.New("unsupported signal")
	}
	if err := syscall.Kill(-pid, value); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func terminateProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = forwardToProcessGroup(pid, syscall.SIGTERM)
}

func forceKillProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = forwardToProcessGroup(pid, syscall.SIGKILL)
}
