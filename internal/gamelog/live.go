package gamelog

import (
	"bytes"
	"os"
)

// LiveSource incrementally tails a game-owned log. Existing content is
// skipped on open so endpoints from previous sessions cannot corroborate a
// new recording.
type LiveSource struct {
	path   string
	parser Parser
	offset int64
	carry  []byte
}

// OpenLive opens the registered game's default log for incremental parsing.
// A log that does not exist yet is supported and will be read when created.
func OpenLive(gameID string) (*LiveSource, error) {
	p, err := ForGame(gameID)
	if err != nil {
		return nil, err
	}
	path, err := p.DefaultLogPath()
	if err != nil {
		return nil, err
	}
	l := &LiveSource{path: path, parser: p}
	if st, err := os.Stat(path); err == nil {
		l.offset = st.Size()
	}
	return l, nil
}

// TakeCandidates returns endpoint records appended since the previous call.
func (l *LiveSource) TakeCandidates() []Candidate {
	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() < l.offset { // log rotated/truncated
		l.offset, l.carry = 0, nil
	}
	buf := make([]byte, st.Size()-l.offset)
	n, err := f.ReadAt(buf, l.offset)
	if err != nil && n == 0 {
		return nil
	}
	l.offset += int64(n)
	data := append(l.carry, buf[:n]...)
	lines := bytes.Split(data, []byte{'\n'})
	l.carry = append(l.carry[:0], lines[len(lines)-1]...)
	var out []Candidate
	for _, line := range lines[:len(lines)-1] {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		out = append(out, l.parser.ParseLine(string(line))...)
	}
	return out
}

func (l *LiveSource) Close() error { return nil }
