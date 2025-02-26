package v1

// Requirement
type Requirement interface {
	Description() string
	Check() bool
}
