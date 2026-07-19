//go:build windows

package identity

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var crypt32 = windows.NewLazySystemDLL("crypt32.dll")
var cryptProtectData = crypt32.NewProc("CryptProtectData")
var cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var localFree = kernel32.NewProc("LocalFree")

func blob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{uint32(len(b)), &b[0]}
}
func blobBytes(b dataBlob) []byte {
	if b.cbData == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(b.pbData, b.cbData)...)
}
func protect(in []byte) ([]byte, error) {
	src := blob(in)
	var out dataBlob
	r, _, e := cryptProtectData.Call(uintptr(unsafe.Pointer(&src)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", e)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return blobBytes(out), nil
}
func unprotect(in []byte) ([]byte, error) {
	src := blob(in)
	var out dataBlob
	r, _, e := cryptUnprotectData.Call(uintptr(unsafe.Pointer(&src)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", e)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return blobBytes(out), nil
}
