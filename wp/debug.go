package wp

import (
	"fmt"
	"os"
)

var debugEnabled bool

// SetDebug toggles verbose detection logging to stderr for the wp package.
func SetDebug(on bool) { debugEnabled = on }

func debugf(format string, args ...any) {
	if !debugEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
}
