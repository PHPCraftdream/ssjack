package approvals

import (
	"strconv"
	"unicode/utf8"
)

func display(value string) (string, bool) {
	if !utf8.ValidString(value) {
		return "", false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return "", false
		}
	}
	return strconv.Quote(value), true
}
