//go:build windows

package gamelog

import (
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const rlLogRelPath = `My Games\Rocket League\TAGame\Logs\Launch.log`

var (
	wtsapi32            = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQueryToken   = wtsapi32.NewProc("WTSQueryUserToken")
	kernel32Mod         = windows.NewLazySystemDLL("kernel32.dll")
	procActiveConsoleID = kernel32Mod.NewProc("WTSGetActiveConsoleSessionId")
)

func (RocketLeagueParser) DefaultLogPath() (string, error) {
	// When running as the logged-in user (pingrank CLI), FOLDERID_Documents
	// points directly to their profile.
	if documents, err := windows.KnownFolderPath(windows.FOLDERID_Documents, 0); err == nil {
		p := filepath.Join(documents, rlLogRelPath)
		if _, statErr := os.Stat(p); statErr == nil {
			return p, nil
		}
		// Under LocalSystem (pingrank-service.exe), FOLDERID_Documents points
		// at systemprofile\Documents; resolve the active user's Documents via
		// their WTS token so live log corroboration works in service mode.
		if userDocs, uerr := activeUserDocuments(); uerr == nil && userDocs != "" {
			return filepath.Join(userDocs, rlLogRelPath), nil
		}
		return p, nil
	}
	userDocs, err := activeUserDocuments()
	if err != nil {
		return "", err
	}
	return filepath.Join(userDocs, rlLogRelPath), nil
}

func activeUserDocuments() (string, error) {
	sid, _, _ := procActiveConsoleID.Call()
	if sid == 0xFFFFFFFF {
		return "", windows.ERROR_NO_SUCH_LOGON_SESSION
	}
	var token windows.Token
	r1, _, err := procWTSQueryToken.Call(sid, uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(&token)
	if r1 == 0 {
		return "", err
	}
	defer token.Close()
	return token.KnownFolderPath(windows.FOLDERID_Documents, 0)
}
