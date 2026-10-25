package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var Version = "dev"
var Commit = "unknown"

func Revision() string {
	if Commit != "unknown" && Commit != "" {
		return Commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return "unknown"
}

func String() string {
	return fmt.Sprintf("ssjack %s (commit %s; %s/%s; %s)", Version, Revision(), runtime.GOOS, runtime.GOARCH, runtime.Version())
}
