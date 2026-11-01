package main

import (
	"fmt"
	"os"

	"pingrank.gg/internal/update"
)

// cmdUpdates shows or changes whether the service installs new releases
// by itself. Changing it needs an administrator terminal.
func cmdUpdates(args []string) int {
	if len(args) == 0 {
		state := "on"
		if !update.Enabled() {
			state = "off"
		}
		fmt.Println("automatic updates:", state)
		return 0
	}
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		fmt.Fprintln(os.Stderr, "usage: pingrank updates [on|off]")
		return 2
	}
	if err := update.SetEnabled(args[0] == "on"); err != nil {
		fmt.Fprintln(os.Stderr, "pingrank: changing the update setting needs an administrator terminal:", err)
		return 1
	}
	fmt.Println("automatic updates:", args[0])
	return 0
}
