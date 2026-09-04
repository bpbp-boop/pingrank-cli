package flows

// Riot's port-forwarding table is a service hint, not proof of a match:
// https://support.riotgames.com/en-us/valorant/support-tools/how-to-set-up-port-forwarding/
// Keep this mapping in sync between the separate server and Windows modules.
// Do not classify arbitrary TCP ports as voice: Riot's configurable local
// forwarding range is not a remote service signature.
func ValorantRole(proto string, port uint16) string {
	if proto == "udp" {
		switch {
		case port >= 7000 && port <= 8000, port == 8180, port == 8181:
			return "game"
		case port >= 27016 && port <= 27024, port >= 54000 && port <= 54012:
			return "voice"
		}
	}
	if (proto == "udp" || proto == "tcp") && port == 8088 {
		return "spectator"
	}
	if proto == "tcp" {
		switch {
		case port == 2099, port == 5222, port == 5223, port == 80, port == 443,
			port >= 8393 && port <= 8400:
			return "platform"
		}
	}
	return "unknown"
}
