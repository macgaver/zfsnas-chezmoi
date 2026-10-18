package system

import (
	"strings"
	"testing"
)

// Issue #175: every ZNAS snapshot name must be accepted (UTC timestamps).
func TestShadowCopyParams(t *testing.T) {
	for _, f := range []string{"", DefaultShadowCopyFormat} {
		got := shadowCopyParams(f)
		for _, want := range []string{
			`   shadow:snapprefix = ^[A-Za-z0-9_-]\{1,\}$` + "\n",
			"   shadow:delimiter = -20\n",
			"   shadow:format = -%Y%m%d-%H%M%S\n",
			"   shadow:localtime = no\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("format %q: missing %q in:\n%s", f, want, got)
			}
		}
	}
	got := shadowCopyParams("daily-%Y.%m.%d")
	if strings.Contains(got, "snapprefix") || !strings.Contains(got, "   shadow:format = daily-%Y.%m.%d\n") ||
		!strings.Contains(got, "   shadow:localtime = no\n") {
		t.Errorf("custom format must match exactly (UTC):\n%s", got)
	}
}
