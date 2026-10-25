package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

func readVisibleInput(prompt string, allowEmpty bool) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("an interactive terminal is required for confirmation")
	}
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}
	return readVisibleLine(os.Stdin, allowEmpty)
}

func readVisibleLine(input io.Reader, allowEmpty bool) ([]byte, error) {
	var line []byte
	var next [1]byte
	for {
		// Do not buffer ahead into the next secret prompt.
		if _, err := io.ReadFull(input, next[:]); err != nil {
			clear(line)
			return nil, errors.New("failed to read terminal input")
		}
		if next[0] == '\n' {
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if !allowEmpty && len(line) == 0 {
				return nil, errors.New("terminal input must not be empty")
			}
			return line, nil
		}
		line = append(line, next[0])
		if len(line) > 16*1024 && (len(line) != 16*1024+1 || next[0] != '\r') {
			clear(line)
			return nil, errors.New("terminal input exceeds 16384 bytes")
		}
	}
}

func confirmVisibleValue(prompt, expected string) error {
	value, err := readVisibleInput(prompt, false)
	if err != nil {
		return err
	}
	defer clear(value)
	if string(value) != expected {
		return errors.New("confirmation did not match; operation cancelled")
	}
	return nil
}
