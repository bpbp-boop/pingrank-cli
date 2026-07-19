//go:build windows

package gamelog

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func (RocketLeagueParser) DefaultLogPath() (string, error) {
	documents, err := windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(documents, "My Games", "Rocket League", "TAGame", "Logs", "Launch.log"), nil
}
