// Package submit implements milestone 5: building the v1 submission
// payload from a recorded session and delivering it to the ingest backend.
// The payload is per-segment derived stats + game ID + client version,
// nothing else — no samples, no local IP, no hostname, no user identifier.
// The server derives the submitter's ASN from the connection and discards
// the address.
package submit

import (
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/cgnat"
	"pingrank.gg/internal/session"
)

// SchemaVersion is the submission payload version ("v").
const SchemaVersion = 1

// DefaultServerURL is the production ingest endpoint. Override with
// -server or the PINGRANK_SERVER environment variable.
const DefaultServerURL = "https://ingest.pingrank.gg"

// Payload is one submitted session.
type Payload struct {
	V             int     `json:"v"`
	ClientVersion string  `json:"clientVersion"`
	Session       Session `json:"session"`
}

// Session is the per-session envelope.
type Session struct {
	GameID            string             `json:"gameId"`
	Start             time.Time          `json:"start"`
	End               time.Time          `json:"end"`
	EndReason         string             `json:"endReason,omitempty"`
	UDPDiscovery      string             `json:"udpDiscovery,omitempty"`
	CGNAT             string             `json:"cgnat,omitempty"`
	CGNATEvidence     *cgnat.Evidence    `json:"cgnatEvidence,omitempty"`
	LocalAddressClass string             `json:"localAddressClass,omitempty"`
	AgentID           string             `json:"agentId,omitempty"`
	AccessPath        *accesspath.Result `json:"accessPath,omitempty"`
	Segments          []Segment          `json:"segments"`
}

// Segment is one server-endpoint binding with its derived stats. Endpoint
// is the game server's address, never ours.
type Segment struct {
	Seq               int                      `json:"seq"`
	Proto             string                   `json:"proto,omitempty"`
	Endpoint          string                   `json:"endpoint,omitempty"`
	Relay             bool                     `json:"relay,omitempty"`
	RelayLabel        string                   `json:"relayLabel,omitempty"`
	Confidence        string                   `json:"confidence,omitempty"`
	Source            string                   `json:"source,omitempty"`
	Role              string                   `json:"role,omitempty"`
	Eligibility       string                   `json:"eligibility,omitempty"`
	EligibilityReason string                   `json:"eligibilityReason,omitempty"`
	CorroboratedBy    string                   `json:"corroboratedBy,omitempty"`
	Traffic           *session.TrafficEvidence `json:"traffic,omitempty"`
	Start             time.Time                `json:"start"`
	Stats             session.SegmentStats     `json:"stats"`
}

// Build converts a session summary into the submission payload.
func Build(sum session.Summary, clientVersion string) Payload {
	endReason := sum.EndReason
	if sum.Truncated {
		endReason = "truncated"
	}
	segs := make([]Segment, 0, len(sum.Segments))
	for _, s := range sum.Segments {
		segs = append(segs, Segment{
			Seq:        s.Seq,
			Proto:      s.Proto,
			Endpoint:   s.Endpoint,
			Relay:      s.Relay,
			RelayLabel: s.RelayLabel,
			Confidence: s.Confidence,
			Source:     s.Source,
			Role:       s.Role, Eligibility: s.Eligibility,
			EligibilityReason: s.EligibilityReason, CorroboratedBy: s.CorroboratedBy,
			Traffic: s.Traffic,
			Start:   s.Start,
			Stats:   s.Stats,
		})
	}
	return Payload{
		V:             SchemaVersion,
		ClientVersion: clientVersion,
		Session: Session{
			GameID:            sum.GameID,
			Start:             sum.Start,
			End:               sum.End,
			EndReason:         endReason,
			UDPDiscovery:      sum.UDPDiscovery,
			CGNAT:             sum.CGNAT,
			CGNATEvidence:     sum.CGNATEvidence,
			LocalAddressClass: sum.LocalAddressClass,
			AgentID:           sum.AgentID,
			AccessPath:        sum.AccessPath,
			Segments:          segs,
		},
	}
}
