// Command pingrank-tray provides a minimal native Windows notification-area
// companion for the PingRank service. It has no console and no network access;
// it reads the service's machine-local status snapshot.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"pingrank.gg/internal/agent"
	"pingrank.gg/internal/identity"
)

const (
	wmDestroy       = 0x0002
	wmCommand       = 0x0111
	wmRButtonUp     = 0x0205
	wmLButtonDbl    = 0x0203
	wmApp           = 0x8000
	wmTray          = wmApp + 1
	wmRefresh       = wmApp + 2
	cwUseDefault    = 0x80000000
	wsOverlapped    = 0x00000000
	nimAdd          = 0x00000000
	nimModify       = 0x00000001
	nimDelete       = 0x00000002
	nifMessage      = 0x00000001
	nifIcon         = 0x00000002
	nifTip          = 0x00000004
	imageIcon       = 1
	lrLoadFromFile  = 0x00000010
	lrDefaultSize   = 0x00000040
	mfString        = 0x00000000
	mfGray          = 0x00000001
	mfSeparator     = 0x00000800
	tpmRightButton  = 0x0002
	swShowNormal    = 1
	menuOpen        = 1001
	menuExit        = 1002
	menuWebSessions = 1003

	// websiteURL is the public site; the tray opens it in the default browser
	// via the shell, so the tray binary itself still performs no network I/O.
	websiteURL = "https://pingrank.gg"
)

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	shell32                 = windows.NewLazySystemDLL("shell32.dll")
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procPostMessage         = user32.NewProc("PostMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procLoadIcon            = user32.NewProc("LoadIconW")
	procLoadImage           = user32.NewProc("LoadImageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenu          = user32.NewProc("AppendMenuW")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procShellNotifyIcon     = shell32.NewProc("Shell_NotifyIconW")
	procShellExecute        = shell32.NewProc("ShellExecuteW")
	procShellExecuteEx      = shell32.NewProc("ShellExecuteExW")
	procGetModuleHandle     = kernel32.NewProc("GetModuleHandleW")

	trayDataDir string
	trayIcon    uintptr
	trayStatus  = "PingRank.gg service status unavailable"
)

type point struct{ X, Y int32 }

type message struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSmall  uintptr
}

type notifyIconData struct {
	Size        uint32
	HWnd        uintptr
	ID          uint32
	Flags       uint32
	CallbackMsg uint32
	Icon        uintptr
	Tip         [128]uint16
	State       uint32
	StateMask   uint32
	Info        [256]uint16
	Version     uint32
	InfoTitle   [64]uint16
	InfoFlags   uint32
	GUID        windows.GUID
	BalloonIcon uintptr
}

type shellExecuteInfo struct {
	Size       uint32
	Mask       uint32
	HWnd       uintptr
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   uintptr
	IDList     uintptr
	Class      *uint16
	ClassKey   windows.Handle
	HotKey     uint32
	Icon       uintptr
	Process    windows.Handle
}

func main() {
	runtime.LockOSThread()
	trayLog("starting")
	name, _ := windows.UTF16PtrFromString(`Local\PingRankGGTray`)
	mutex, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		trayLog("another tray instance owns the mutex")
		return
	}
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	trayDataDir, err = agent.DefaultDataDir()
	if err != nil {
		trayLog("data directory: " + err.Error())
		return
	}
	startup := len(os.Args) > 1 && os.Args[1] == "--startup"
	if startup && trayDisabled() {
		trayLog("startup suppressed by the user-disabled marker")
		return
	}
	trayLog("checking service status")
	if !ensureServiceRunning(!startup) {
		trayLog("service is not running and could not be started")
		return
	}
	trayLog("service is running")
	if !startup {
		setTrayDisabled(false)
	}
	if err := runTray(); err != nil {
		trayLog("tray window: " + err.Error())
		return
	}
	trayLog("stopped")
}

func runTray() error {
	trayLog("registering tray window class")
	className, _ := windows.UTF16PtrFromString("PingRankGGTrayWindow")
	instance, _, _ := procGetModuleHandle.Call(0)
	icon := loadAppIcon()
	trayIcon = icon
	class := wndClassEx{
		Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: windows.NewCallback(windowProc),
		Instance: instance, Icon: icon, IconSmall: icon, ClassName: className,
	}
	if atom, _, callErr := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return fmt.Errorf("RegisterClassExW: %w", callErr)
	}
	trayLog("creating tray window")
	hwnd, _, callErr := procCreateWindowEx.Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)), wsOverlapped,
		cwUseDefault, cwUseDefault, 0, 0, 0, 0, instance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW: %w", callErr)
	}
	trayLog(fmt.Sprintf("tray window created: 0x%x", hwnd))
	refreshStatus(hwnd)
	trayLog("adding notification icon")
	if !notifyIcon(nimAdd, hwnd, icon, trayStatus) {
		return fmt.Errorf("Shell_NotifyIconW failed")
	}
	trayLog("notification icon added")
	defer notifyIcon(nimDelete, hwnd, 0, "")

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				procPostMessage.Call(hwnd, wmRefresh, 0, 0)
			case <-stop:
				return
			}
		}
	}()

	var msg message
	for {
		result, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return nil
}

func windowProc(hwnd, rawMsg, wParam, lParam uintptr) uintptr {
	msg := uint32(rawMsg)
	switch msg {
	case wmRefresh:
		refreshStatus(hwnd)
		return 0
	case wmTray:
		switch uint32(lParam) {
		case wmRButtonUp:
			showMenu(hwnd)
		case wmLButtonDbl:
			openSessions(hwnd)
		}
		return 0
	case wmCommand:
		switch uint16(wParam) {
		case menuOpen:
			openSessions(hwnd)
		case menuWebSessions:
			openWebSessions(hwnd)
		case menuExit:
			if stopService() {
				setTrayDisabled(true)
				procPostQuitMessage.Call(0)
			} else {
				trayStatus = "PingRank.gg: service stop was cancelled or failed"
				notifyIcon(nimModify, hwnd, trayIcon, trayStatus)
			}
		}
		return 0
	case wmDestroy:
		trayLog("tray window received WM_DESTROY")
		procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProc.Call(hwnd, rawMsg, wParam, lParam)
	return result
}

func refreshStatus(hwnd uintptr) {
	status, err := agent.ReadStatus(agent.StatusPath(trayDataDir))
	if err != nil {
		trayStatus = "PingRank.gg service status unavailable"
	} else {
		trayStatus = "PingRank.gg: " + status.Message
		if status.Endpoint != "" {
			trayStatus = "PingRank.gg: " + status.Game + " - " + status.Endpoint
		}
	}
	notifyIcon(nimModify, hwnd, trayIcon, trayStatus)
}

func notifyIcon(action uint32, hwnd, icon uintptr, tip string) bool {
	data := notifyIconData{
		Size: uint32(unsafe.Sizeof(notifyIconData{})), HWnd: hwnd, ID: 1,
		Flags: nifMessage | nifIcon | nifTip, CallbackMsg: wmTray, Icon: icon,
	}
	copyUTF16(data.Tip[:], tip)
	result, _, _ := procShellNotifyIcon.Call(uintptr(action), uintptr(unsafe.Pointer(&data)))
	return result != 0
}

func showMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	appendMenu(menu, mfString|mfGray, 0, truncate(trayStatus, 72))
	procAppendMenu.Call(menu, mfSeparator, 0, 0)
	if _, err := identity.Load(filepath.Join(trayDataDir, "install.json")); err == nil {
		appendMenu(menu, mfString, menuWebSessions, "View my sessions on pingrank.gg")
	} else {
		appendMenu(menu, mfString|mfGray, 0, "View my sessions (no uploads yet)")
	}
	appendMenu(menu, mfString, menuOpen, "Open PingRank.gg logs")
	appendMenu(menu, mfString, menuExit, "Exit PingRank.gg (stop service)")
	var cursor point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&cursor)))
	procSetForegroundWindow.Call(hwnd)
	procTrackPopupMenu.Call(menu, tpmRightButton, uintptr(cursor.X), uintptr(cursor.Y), 0, hwnd, 0)
}

func appendMenu(menu uintptr, flags uint32, id uint16, label string) {
	value, _ := windows.UTF16PtrFromString(label)
	procAppendMenu.Call(menu, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(value)))
}

func openSessions(hwnd uintptr) {
	path := filepath.Join(trayDataDir, "sessions")
	_ = os.MkdirAll(path, 0o755)
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(path)
	procShellExecute.Call(hwnd, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, swShowNormal)
}

// openWebSessions opens this installation's session history on the website.
// The agent ID in the URL is the capability that scopes the page.
func openWebSessions(hwnd uintptr) {
	id, err := identity.Load(filepath.Join(trayDataDir, "install.json"))
	if err != nil {
		trayLog("view my sessions unavailable: " + err.Error())
		trayStatus = "PingRank.gg: no sessions uploaded yet"
		notifyIcon(nimModify, hwnd, trayIcon, trayStatus)
		return
	}
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(websiteURL + "/agents/" + id)
	procShellExecute.Call(hwnd, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, swShowNormal)
}

func trayLog(message string) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return
	}
	dir := filepath.Join(base, "PingRank.gg")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "tray.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), message)
}

func loadAppIcon() uintptr {
	exe, err := os.Executable()
	if err == nil {
		path, _ := windows.UTF16PtrFromString(filepath.Join(filepath.Dir(exe), "pingrank.ico"))
		if icon, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(path)), imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize); icon != 0 {
			return icon
		}
	}
	icon, _, _ := procLoadIcon.Call(0, 32512) // IDI_APPLICATION fallback
	return icon
}

func disabledMarker() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return ""
	}
	return filepath.Join(base, "PingRank.gg", "tray-disabled")
}

func trayDisabled() bool {
	path := disabledMarker()
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func setTrayDisabled(disabled bool) {
	path := disabledMarker()
	if path == "" {
		return
	}
	if !disabled {
		_ = os.Remove(path)
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte("stopped\n"), 0o600)
}

func queryService() (svc.State, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return svc.Stopped, err
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString("PingRank")
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return svc.Stopped, err
	}
	service := &mgr.Service{Name: "PingRank", Handle: handle}
	defer service.Close()
	status, err := service.Query()
	return status.State, err
}

func waitForService(want svc.State, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := queryService()
		if err == nil && state == want {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func ensureServiceRunning(allowElevation bool) bool {
	state, err := queryService()
	if err == nil && state == svc.Running {
		return true
	}
	if state == svc.StartPending && waitForService(svc.Running, 10*time.Second) {
		return true
	}
	if !allowElevation || !runElevatedServiceCommand("start") {
		return false
	}
	return waitForService(svc.Running, 15*time.Second)
}

func stopService() bool {
	state, err := queryService()
	if err == nil && state == svc.Stopped {
		return true
	}
	if !runElevatedServiceCommand("stop") {
		return false
	}
	return waitForService(svc.Stopped, 25*time.Second)
}

func runElevatedServiceCommand(command string) bool {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return false
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(filepath.Join(systemRoot, "System32", "sc.exe"))
	parameters, _ := windows.UTF16PtrFromString(command + " PingRank")
	info := shellExecuteInfo{
		Size: uint32(unsafe.Sizeof(shellExecuteInfo{})), Mask: 0x00000040, // SEE_MASK_NOCLOSEPROCESS
		Verb: verb, File: file, Parameters: parameters, Show: 0,
	}
	result, _, _ := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 || info.Process == 0 {
		return false
	}
	defer windows.CloseHandle(info.Process)
	_, _ = windows.WaitForSingleObject(info.Process, windows.INFINITE)
	var exitCode uint32
	return windows.GetExitCodeProcess(info.Process, &exitCode) == nil && exitCode == 0
}

func copyUTF16(dst []uint16, value string) {
	encoded, _ := windows.UTF16FromString(truncate(value, len(dst)-1))
	copy(dst, encoded)
}

func truncate(value string, length int) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	runes := []rune(value)
	if len(runes) > length {
		return string(runes[:length-1]) + "…"
	}
	return value
}
