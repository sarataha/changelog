package output

import (
	"fmt"
	"strings"

	"github.com/sarataha/changelog/internal/audit"
)

// OutputFormatter defines the interface for formatting system actions
type OutputFormatter interface {
	Format(action *audit.SystemAction) string
}

// SimpleFormatter provides basic structured formatting
type SimpleFormatter struct{}

// NewSimpleFormatter creates a new simple formatter
func NewSimpleFormatter() *SimpleFormatter {
	return &SimpleFormatter{}
}

// Format converts a SystemAction to a human-readable string
func (f *SimpleFormatter) Format(action *audit.SystemAction) string {
	if action.Target == "" {
		return fmt.Sprintf("%s %s performed %s using %s",
			action.Timestamp, action.User, action.Action, action.Process)
	}

	switch action.Action {
	case "openat", "open":
		return fmt.Sprintf("%s %s opened %s using %s",
			action.Timestamp, action.User, action.Target, action.Process)
	case "write":
		return fmt.Sprintf("%s %s wrote to %s using %s",
			action.Timestamp, action.User, action.Target, action.Process)
	case "unlink", "unlinkat":
		return fmt.Sprintf("%s %s deleted %s using %s",
			action.Timestamp, action.User, action.Target, action.Process)
	case "execve":
		if strings.HasPrefix(action.Process, "systemctl") {
			return fmt.Sprintf("%s %s executed: systemctl %s",
				action.Timestamp, action.User, action.Target)
		}
		return fmt.Sprintf("%s %s executed: %s %s",
			action.Timestamp, action.User, action.Process, action.Target)
	default:
		return fmt.Sprintf("%s %s performed %s on %s using %s",
			action.Timestamp, action.User, action.Action, action.Target, action.Process)
	}
}

// HumanFormatter is an alias for SimpleFormatter (for future extensibility)
type HumanFormatter struct {
	*SimpleFormatter
}

// NewHumanFormatter creates a new human formatter
func NewHumanFormatter() *HumanFormatter {
	return &HumanFormatter{
		SimpleFormatter: NewSimpleFormatter(),
	}
}