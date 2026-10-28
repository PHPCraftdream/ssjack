package operationstore

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

func invalidSurrogateEscape(b []byte) bool {
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		if escaped {
			escaped = false
			if c == 'u' && i+4 < len(b) {
				v, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
				if err == nil && v >= 0xd800 && v <= 0xdfff {
					return true
				}
				i += 4
			}
			continue
		}
		if c == '\\' {
			escaped = true
		} else if c == '"' {
			inString = false
		}
	}
	return false
}

func parseState(b []byte) (state, error) {
	// encoding/json normalizes malformed UTF-8 and lone surrogate escapes.
	if !utf8.Valid(b) || invalidSurrogateEscape(b) {
		return state{}, ErrUnavailable
	}
	var st state
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return state{}, ErrUnavailable
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return state{}, ErrUnavailable
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return state{}, ErrUnavailable
		}
		seen[k] = true
		switch k {
		case "version":
			err = decodeNonNull(d, &st.Version)
		case "quarantined":
			err = decodeNonNull(d, &st.Quarantined)
		case "records":
			st.Records, err = parseRecords(d)
		default:
			return state{}, ErrUnavailable
		}
		if err != nil {
			return state{}, ErrUnavailable
		}
	}
	if _, err = d.Token(); err != nil {
		return state{}, ErrUnavailable
	}
	if !seen["version"] || !seen["records"] || !seen["quarantined"] || st.Version != 1 || len(st.Records) > maxRecords {
		return state{}, ErrUnavailable
	}
	if _, err = d.Token(); err != io.EOF {
		return state{}, ErrUnavailable
	}
	seenKeys := map[string]bool{}
	resources := map[struct{ target, resource string }]bool{}
	for _, r := range st.Records {
		if !valid(r.Key) || !valid(r.CanonicalTarget) || !valid(r.CanonicalResource) || !digest(r.PlanDigest) || seenKeys[r.Key] {
			return state{}, ErrUnavailable
		}
		pair := struct{ target, resource string }{r.CanonicalTarget, r.CanonicalResource}
		if resources[pair] {
			return state{}, ErrUnavailable
		}
		seenKeys[r.Key], resources[pair] = true, true
	}
	if st.Quarantined {
		for _, r := range st.Records {
			if !r.Quarantined {
				return state{}, ErrUnavailable
			}
		}
		return st, ErrConflict
	}
	for _, r := range st.Records {
		if r.Quarantined {
			return state{}, ErrUnavailable
		}
	}
	return st, nil
}

func parseRecords(d *json.Decoder) ([]Reservation, error) {
	t, err := d.Token()
	if err != nil || t != json.Delim('[') {
		return nil, ErrUnavailable
	}
	records := make([]Reservation, 0)
	for d.More() {
		t, err = d.Token()
		if err != nil || t != json.Delim('{') {
			return nil, ErrUnavailable
		}
		r := Reservation{}
		seen := map[string]bool{}
		for d.More() {
			t, err = d.Token()
			if err != nil {
				return nil, ErrUnavailable
			}
			k, ok := t.(string)
			if !ok || seen[k] {
				return nil, ErrUnavailable
			}
			seen[k] = true
			switch k {
			case "key":
				err = decodeNonNull(d, &r.Key)
			case "canonical_target":
				err = decodeNonNull(d, &r.CanonicalTarget)
			case "canonical_resource":
				err = decodeNonNull(d, &r.CanonicalResource)
			case "plan_digest":
				err = decodeNonNull(d, &r.PlanDigest)
			case "quarantined":
				err = decodeNonNull(d, &r.Quarantined)
			default:
				return nil, ErrUnavailable
			}
			if err != nil {
				return nil, ErrUnavailable
			}
		}
		if _, err = d.Token(); err != nil || len(seen) != 5 || !seen["quarantined"] {
			return nil, ErrUnavailable
		}
		records = append(records, r)
	}
	_, err = d.Token()
	return records, err
}

func validateState(st state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return ErrUnavailable
	}
	_, err = parseState(b)
	return err
}

func decodeNonNull(d *json.Decoder, v any) error {
	var raw json.RawMessage
	if err := d.Decode(&raw); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrUnavailable
	}
	return json.Unmarshal(raw, v)
}
