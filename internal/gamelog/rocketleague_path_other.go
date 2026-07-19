//go:build !windows

package gamelog

import "fmt"

func (RocketLeagueParser) DefaultLogPath() (string, error) {
	return "", fmt.Errorf("Rocket League default log path is only available on Windows")
}
