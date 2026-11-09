//go:build windows

package routing

import (
	"fmt"
	"os"
	"syscall"
)

// txObjectIdentity returns the identity of the filesystem object at path.
// Windows exposes it as the volume serial number together with the file
// index; the handle is opened read-only and never written.
func txObjectIdentity(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%d", uint32(info.VolumeSerialNumber), info.FileIndexHigh, info.FileIndexLow), nil
}
