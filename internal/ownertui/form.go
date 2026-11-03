package ownertui

import (
	"strings"
	"unicode/utf8"
)

type field struct {
	label  string
	help   string
	value  []byte
	secret bool
	limit  int
}

type form struct {
	action string
	fields []field
	focus  int
	origin location
}

func (f *form) clear() {
	for i := range f.fields {
		clear(f.fields[i].value)
		f.fields[i].value = nil
	}
}

func (f *form) move(delta int) {
	count := len(f.fields) + 2
	f.focus = (f.focus + delta + count) % count
}

func (f *form) insert(text string) {
	if f.focus >= len(f.fields) || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r\n\x1b") {
		return
	}
	current := &f.fields[f.focus]
	if len(text) > current.limit-len(current.value) {
		return
	}
	if cap(current.value) < current.limit {
		owned := make([]byte, len(current.value), current.limit)
		copy(owned, current.value)
		clear(current.value)
		current.value = owned
	}
	current.value = append(current.value, text...)
}

func (f *form) backspace() {
	if f.focus >= len(f.fields) {
		return
	}
	current := &f.fields[f.focus]
	if len(current.value) == 0 {
		return
	}
	_, size := utf8.DecodeLastRune(current.value)
	start := len(current.value) - size
	clear(current.value[start:])
	current.value = current.value[:start]
}

func (f *form) display(index int) string {
	current := &f.fields[index]
	if current.secret {
		if len(current.value) == 0 {
			return "<hidden; empty>"
		}
		return "<hidden; entered>"
	}
	return escaped(string(current.value))
}
