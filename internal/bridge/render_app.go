package bridge

import (
	"fmt"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/application"
)

// renderApps lists the registered applications, one per line. An empty list
// says so and repeats the keeper's hint.
func renderApps(list application.ListOutput) string {
	var lines []string
	switch len(list.Applications) {
	case 0:
		lines = append(lines, "No applications are registered.")
	case 1:
		lines = append(lines, "1 registered application:")
	default:
		lines = append(lines, fmt.Sprintf("%d registered applications:", len(list.Applications)))
	}
	for _, app := range list.Applications {
		detail := "profile " + app.Profile
		if app.Container != "" {
			detail += ", container " + app.Container
		}
		lines = append(lines, fmt.Sprintf("- %s (%s)", app.Name, detail))
	}
	if list.Hint != "" {
		lines = append(lines, "Hint: "+oneLine(list.Hint))
	}
	return strings.Join(lines, "\n")
}
