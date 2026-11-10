package sshstatus

import (
	"fmt"
	"strconv"
)

type Status struct {
	Profile           string
	DesiredRevision   uint64
	DesiredKnown      bool
	DeliveredRevision uint64
	DeliveredKnown    bool
	AdoptedRevision   uint64
	AdoptedKnown      bool
	Unavailable       bool
}

func (s *Status) String() string {
	return s.Display()
}

func (s *Status) Display() string {
	if s == nil {
		return ""
	}
	revision := func(known bool, value uint64) string {
		if !known {
			return "unknown"
		}
		return strconv.FormatUint(value, 10)
	}
	return "\nSSH last observed: profile=" + fmt.Sprintf("%q", s.Profile) +
		" desired=" + revision(s.DesiredKnown, s.DesiredRevision) +
		" delivered=" + revision(s.DeliveredKnown, s.DeliveredRevision) +
		" adopted=" + revision(s.AdoptedKnown, s.AdoptedRevision) +
		" unavailable=" + strconv.FormatBool(s.Unavailable)
}
