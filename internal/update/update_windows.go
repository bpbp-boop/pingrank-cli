package update

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// settingsKey holds machine-wide settings under HKLM. Only administrators
// can write it, so the service can trust what it reads there.
const settingsKey = `SOFTWARE\PingRank.gg`

const (
	valueAutoUpdate   = "AutoUpdate"   // DWORD; 0 turns updates off
	valueRelaunchTray = "RelaunchTray" // DWORD; set while an update runs
)

// stagePrefix names the folders that hold downloaded installers.
const stagePrefix = "pingrank-update-"

// Enabled reports whether automatic updates are on. They are on unless an
// administrator set AutoUpdate to 0.
func Enabled() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, settingsKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(valueAutoUpdate)
	return err != nil || v != 0
}

// SetEnabled turns automatic updates on or off. It needs administrator
// rights.
func SetEnabled(on bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, settingsKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	var v uint32
	if on {
		v = 1
	}
	return k.SetDWordValue(valueAutoUpdate, v)
}

// MarkTrayRelaunch records that the tray closed for an update, so the
// service can start it again afterwards.
func MarkTrayRelaunch() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, settingsKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(valueRelaunchTray, 1)
}

// TakeTrayRelaunch reports and clears the mark from MarkTrayRelaunch.
func TakeTrayRelaunch() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(valueRelaunchTray)
	if err != nil {
		return false
	}
	_ = k.DeleteValue(valueRelaunchTray)
	return v != 0
}

// Stage makes a new folder in the system temp folder that only SYSTEM and
// administrators can open. Its name is random, so nobody can create it in
// advance.
func Stage() (string, error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for range 5 {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		dir := filepath.Join(os.TempDir(), stagePrefix+hex.EncodeToString(b[:]))
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(p, sa)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return "", err
		}
	}
	return "", errors.New("could not make a staging folder")
}

// CleanStaged removes installers left by earlier updates. It keeps the
// Windows Installer log of the last week's attempts and touches only
// folders that LocalSystem owns.
func CleanStaged() {
	tmp := os.TempDir()
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), stagePrefix) {
			continue
		}
		dir := filepath.Join(tmp, e.Name())
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !ownedBySystem(dir) {
			continue
		}
		if time.Since(info.ModTime()) > 7*24*time.Hour {
			_ = os.RemoveAll(dir)
			continue
		}
		msis, _ := filepath.Glob(filepath.Join(dir, "*.msi"))
		for _, m := range msis {
			_ = os.Remove(m)
		}
	}
}

func ownedBySystem(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	return err == nil && owner.IsWellKnown(windows.WinLocalSystemSid)
}

// Verify checks that Windows trusts the installer's Authenticode signature
// and that SignerName signed it.
func Verify(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return fmt.Errorf("signature: %w", verifyErr)
	}
	name, err := signerName(p)
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	if name != SignerName {
		return fmt.Errorf("signed by %q, not %q", name, SignerName)
	}
	return nil
}

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32.NewProc("CryptMsgClose")
)

const cmsgSignerCertInfoParam = 7

// signerName reads the common name of the certificate that signed the
// file's embedded PKCS #7 signature.
func signerName(path *uint16) (string, error) {
	var encoding, contentType, formatType uint32
	var store, msg windows.Handle
	err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(path),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encoding, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var size uint32
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", e
	}
	buf := make([]byte, size)
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", e
	}
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0, windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&buf[0]), nil)
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(cert)
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if n <= 1 {
		return "", errors.New("certificate has no name")
	}
	name := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], n)
	return windows.UTF16ToString(name), nil
}

// Install starts Windows Installer on the MSI and returns without waiting.
// The installer runs in its own process, outside this service, because
// the upgrade stops and replaces the service. It writes its log next to
// the MSI.
func Install(msiPath, dir string) error {
	msiexec := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	logPath := filepath.Join(dir, "install.log")
	cmdLine := fmt.Sprintf(`"%s" /i "%s" /qn /norestart /l*v "%s"`, msiexec, msiPath, logPath)
	start := func(flags uint32) error {
		cmd := exec.Command(msiexec)
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine, CreationFlags: flags}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	const detached = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
	if err := start(detached | windows.CREATE_BREAKAWAY_FROM_JOB); err != nil {
		// A job that forbids breakaway rejects the flag; try without it.
		return start(detached)
	}
	return nil
}

// LaunchTray starts the tray in every signed-in user's session. Only
// LocalSystem may do this. The tray's --startup flag respects a player who
// closed it on purpose.
func LaunchTray(trayExe string) error {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	var firstErr error
	for _, s := range unsafe.Slice(sessions, count) {
		if s.State != windows.WTSActive {
			continue
		}
		if err := launchInSession(s.SessionID, trayExe); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func launchInSession(session uint32, exe string) error {
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		return err
	}
	defer token.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	cmd, _ := windows.UTF16PtrFromString(`"` + exe + `" --startup`)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, app, cmd, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT, env, dir, si, &pi); err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
