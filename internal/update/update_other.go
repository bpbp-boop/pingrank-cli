//go:build !windows

package update

import "errors"

// The app only updates itself on Windows. These stubs let the portable
// logic build and test elsewhere.

var errUnsupported = errors.New("updates need Windows")

func Enabled() bool                { return false }
func SetEnabled(bool) error        { return errUnsupported }
func MarkTrayRelaunch() error      { return errUnsupported }
func TakeTrayRelaunch() bool       { return false }
func Stage() (string, error)       { return "", errUnsupported }
func CleanStaged()                 {}
func Verify(string) error          { return errUnsupported }
func Install(string, string) error { return errUnsupported }
func LaunchTray(string) error      { return errUnsupported }
