//go:build linux

package runtime

import (
	"fmt"
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
	unlocked := int32(0)
	if err := ptyIoctl(master, syscall.TIOCSPTLCK, unsafe.Pointer(&unlocked)); err != nil {
		closeMaster()
		t.Skipf("cannot unlock PTY: %v", err)
	}
	ptyNumber := uint32(0)
	if err := ptyIoctl(master, syscall.TIOCGPTN, unsafe.Pointer(&ptyNumber)); err != nil {
		closeMaster()
		t.Skipf("cannot determine PTY slave: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptyNumber), os.O_RDWR|syscall.O_NOCTTY, 0)
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
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), request, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
