package tun

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/v2rayA/v2rayA/pkg/util/log"
)

// runPostScript executes the user-defined post-start script.
// On Windows it runs through cmd /C; on other platforms through sh -c.
// Each non-empty line is treated as a separate command.
func runPostScript(script string) {
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", line)
		} else {
			cmd = exec.Command("sh", "-c", line)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Warn("[TUN] Post-start script line %q failed: %v (output: %s)", line, err, strings.TrimSpace(string(out)))
		} else {
			log.Info("[TUN] Post-start: %q -> %s", line, strings.TrimSpace(string(out)))
		}
	}
}
