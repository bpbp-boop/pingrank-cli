//go:build !windows

package identity

// Non-Windows support exists for tests and development builds. Production
// Windows releases use DPAPI in protect_windows.go.
func protect(b []byte) ([]byte, error)   { return append([]byte(nil), b...), nil }
func unprotect(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
