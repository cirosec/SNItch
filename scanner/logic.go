package scanner

type TriState uint8

const (
	TriStateUnknown TriState = iota // default
	TriStateTrue
	TriStateFalse
)
