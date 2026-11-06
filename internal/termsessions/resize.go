package termsessions

import "encoding/json"

// resizeMsg matches the JSON shape the SPA already sends today:
//
//	{"type":"resize","cols":120,"rows":40}
type resizeMsg struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// parseResize returns (cols, rows, true) if data is a well-formed resize
// control message. Anything else returns ok=false so the caller treats the
// frame as raw keyboard input.
func parseResize(data []byte) (uint16, uint16, bool) {
	if len(data) == 0 || data[0] != '{' {
		return 0, 0, false
	}
	var m resizeMsg
	if json.Unmarshal(data, &m) != nil {
		return 0, 0, false
	}
	if m.Type != "resize" {
		return 0, 0, false
	}
	return m.Cols, m.Rows, true
}
