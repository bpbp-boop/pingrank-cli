package gamelog

import (
	"fmt"
	"sort"
	"strings"
)

var parsers = []Parser{RocketLeagueParser{}}

// ForGame returns the registered parser for gameID.
func ForGame(gameID string) (Parser, error) {
	for _, parser := range parsers {
		if strings.EqualFold(parser.GameID(), gameID) {
			return parser, nil
		}
	}
	return nil, fmt.Errorf("no log parser for game %q (available: %s)", gameID, strings.Join(GameIDs(), ", "))
}

// GameIDs lists games with log parsers.
func GameIDs() []string {
	ids := make([]string, 0, len(parsers))
	for _, parser := range parsers {
		ids = append(ids, parser.GameID())
	}
	sort.Strings(ids)
	return ids
}
