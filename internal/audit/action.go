package audit

// SystemAction represents an interpreted system action from audit events
type SystemAction struct {
	Action    string
	Target    string
	Process   string
	User      string
	Timestamp string
}