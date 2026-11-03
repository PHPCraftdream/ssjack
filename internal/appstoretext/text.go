// Package appstoretext performs bounded replacement on explicitly selected
// buffers. It conveys no store access or delivery authority.
package appstoretext

import (
	"bytes"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

const MaxText = 1 << 20
const MaxMappings = 128

var ErrInvalid = errors.New("invalid bounded text replacement")

type Mapping struct {
	Reference appstoreref.Ref
	Value     []byte
}

// Replace substitutes exact placeholders with values, or in reverse maps each
// exact value to its placeholder. Matches are leftmost-longest and nonoverlapping;
// replacement output is never rescanned. Equal references or values are rejected
// in either direction. Values containing "$ssjack" are rejected conservatively,
// since inserted bytes could resemble a registered placeholder. Reverse input is
// rejected only when it contains one of the registered canonical placeholders;
// unknown and malformed marker text is preserved byte-for-byte. Bytes are literal,
// including arbitrary bytes, newlines, and UTF-8, with no escape syntax.
func Replace(input []byte, mappings []Mapping, reverse bool) ([]byte, error) {
	if len(input) > MaxText {
		return nil, ErrInvalid
	}
	placeholders, tokens, err := prepareMappings(mappings, reverse)
	if err != nil {
		return nil, err
	}
	if reverse {
		for _, placeholder := range placeholders {
			if bytes.Contains(input, placeholder) {
				return nil, ErrInvalid
			}
		}
	}

	out := make([]byte, 0, len(input))
	for at := 0; at < len(input); {
		best := -1
		for i, token := range tokens {
			if bytes.HasPrefix(input[at:], token) && (best < 0 || len(token) > len(tokens[best])) {
				best = i
			}
		}
		if best < 0 {
			if len(out) == MaxText {
				clear(out)
				return nil, ErrInvalid
			}
			out = append(out, input[at])
			at++
			continue
		}
		replacement := mappings[best].Value
		if reverse {
			replacement = placeholders[best]
		}
		if len(replacement) > MaxText-len(out) {
			clear(out)
			return nil, ErrInvalid
		}
		out = append(out, replacement...)
		at += len(tokens[best])
	}
	return out, nil
}

func prepareMappings(mappings []Mapping, reverse bool) ([][]byte, [][]byte, error) {
	if len(mappings) == 0 || len(mappings) > MaxMappings {
		return nil, nil, ErrInvalid
	}
	placeholders, tokens := make([][]byte, len(mappings)), make([][]byte, len(mappings))
	for i, m := range mappings {
		if !m.Reference.Valid() || len(m.Value) == 0 || len(m.Value) > MaxText || bytes.Contains(m.Value, []byte("$ssjack")) {
			return nil, nil, ErrInvalid
		}
		placeholder, err := appstoreplaceholder.Encode(m.Reference)
		if err != nil {
			return nil, nil, ErrInvalid
		}
		placeholders[i] = placeholder
		if reverse {
			tokens[i] = m.Value // Borrowed only for this synchronous call.
		} else {
			tokens[i] = placeholder
		}
		for j := 0; j < i; j++ {
			if m.Reference == mappings[j].Reference || bytes.Equal(m.Value, mappings[j].Value) {
				return nil, nil, ErrInvalid
			}
		}
	}
	return placeholders, tokens, nil
}
