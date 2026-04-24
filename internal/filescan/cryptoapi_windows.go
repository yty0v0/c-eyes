//go:build windows

package filescan

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32.NewProc("CryptMsgClose")
)

type cmsgSignerInfo struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

func cryptMsgGetParam(msg windows.Handle, paramType uint32, index uint32, data unsafe.Pointer, dataSize *uint32) error {
	r1, _, e1 := syscall.SyscallN(procCryptMsgGetParam.Addr(), uintptr(msg), uintptr(paramType), uintptr(index), uintptr(data), uintptr(unsafe.Pointer(dataSize)))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func cryptMsgClose(msg windows.Handle) {
	_, _, _ = syscall.SyscallN(procCryptMsgClose.Addr(), uintptr(msg))
}
