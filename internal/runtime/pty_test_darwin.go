//go:build darwin

package runtime

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")
	closeMaster := func() {
		_ = master.Close()
	}
	if err := ptyIoctl(master, syscall.TIOCPTYGRANT, nil); err != nil {
		closeMaster()
		t.Skipf("cannot grant PTY: %v", err)
	}
	if err := ptyIoctl(master, syscall.TIOCPTYUNLK, nil); err != nil {
		closeMaster()
		t.Skipf("cannot unlock PTY: %v", err)
	}
	var name [128]byte
	if err := ptyIoctl(master, syscall.TIOCPTYGNAME, unsafe.Pointer(&name[0])); err != nil {
		closeMaster()
		t.Skipf("cannot determine PTY slave: %v", err)
	}
	nameLength := bytes.IndexByte(name[:], 0)
	if nameLength < 0 {
		closeMaster()
		t.Skip("PTY slave name was not NUL terminated")
	}
	slave, err = os.OpenFile(string(name[:nameLength]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		closeMaster()
		t.Skipf("cannot open PTY slave: %v", err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	return master, slave
}

func ptyIoctl(file *os.File, request uintptr, arg unsafe.Pointer) error {
	var value uintptr
	if arg != nil {
		value = uintptr(arg)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), request, value)
	if errno != 0 {
		return errno
	}
	return nil
}
