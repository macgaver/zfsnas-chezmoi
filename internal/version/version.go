package version

import "time"

// Version is the running build's version. It defaults to the value below for
// local/dev builds, and is overridden at release time by the linker via
//
//	-ldflags "-X zfsnas/internal/version.Version=<tag>"
//
// (see .github/workflows/release.yml). It MUST be a var, not a const — the
// linker's -X can only set variables — and must carry NO leading "v" so it
// compares cleanly against GitHub release tags (which are trimmed of "v").
var Version = "6.7.22"

const ReleasesURL = "https://github.com/macgaver/zfsnas-chezmoi/releases"

var experimentalMode bool

// StartedAt is the wall-clock time the binary was loaded. Captured at
// package init so the same value is returned for the lifetime of the
// process. Used by the frontend to detect server restarts/upgrades — a
// changed StartedAt across two polls means the server bounced, and the
// portal shows the "Server Restarted" refresh popup.
var StartedAt = time.Now()

func SetExperimental(v bool) { experimentalMode = v }
func IsExperimental() bool   { return experimentalMode }
