package startupsecret

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestSourcePrecedenceOwnershipAndSingleConsumption(t *testing.T) {
	for _, argument := range []bool{false, true} {
		i := New("synthetic-environment", true)
		defer i.Close()
		old := i.value
		want := "synthetic-environment"
		if argument {
			want = "synthetic-argument"
			if err := i.Set(want); err != nil || !bytes.Equal(old, make([]byte, len(old))) {
				t.Fatal("argument did not replace and clear environment input")
			}
		}
		called := false
		fallback := func() ([]byte, error) { called = true; return nil, errors.New("unexpected prompt") }
		value, err := i.Read(fallback)
		if err != nil || string(value) != want || called || len(i.value) != 0 {
			t.Fatal("password source changed bytes, retained ownership or prompted")
		}
		clear(value)
		if _, err := i.Read(fallback); !errors.Is(err, ErrConsumed) || called {
			t.Fatal("supplied password was reused or fell back after consumption")
		}
	}
}

func TestAbsentSourcePromptsAndCloseClearsUnusedInput(t *testing.T) {
	i := New("", false)
	called := false
	value, err := i.Read(func() ([]byte, error) { called = true; return []byte("synthetic-terminal"), nil })
	if err != nil || !called || string(value) != "synthetic-terminal" {
		t.Fatal("absent startup source did not use terminal fallback")
	}
	clear(value)
	i.Close()
	if _, err := i.Read(func() ([]byte, error) { t.Fatal("closed source prompted"); return nil, nil }); !errors.Is(err, ErrConsumed) {
		t.Fatal("closed source was usable")
	}
	i = New("synthetic-unused", true)
	owned := i.value
	i.Close()
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("close retained unused password bytes")
	}
}

func TestPasswordBytesAreNotNormalizedAndExactLimitIsAccepted(t *testing.T) {
	for _, value := range []string{"  synthetic-é\npassword\t ", strings.Repeat("s", Maximum)} {
		i := New(value, true)
		password, err := i.Read(func() ([]byte, error) { t.Fatal("valid source prompted"); return nil, nil })
		if err != nil || !bytes.Equal(password, []byte(value)) {
			t.Fatal("valid startup password was normalized or refused at the exact bound")
		}
		clear(password)
		i.Close()
	}
}

func TestInvalidExplicitSourceNeverFallsBackOrEchoes(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("s", Maximum+1)} {
		i := New(value, true)
		if _, err := i.Read(func() ([]byte, error) { t.Fatal("invalid environment prompted"); return nil, nil }); !errors.Is(err, ErrInput) {
			t.Fatal("invalid environment source accepted")
		}
		if err := i.Set("synthetic-override"); err != nil || i.Validate() != nil {
			t.Fatal("explicit valid argument did not override invalid environment")
		}
		i.Close()
		i = New("synthetic-environment", true)
		if err := i.Set(value); err != nil {
			t.Fatal("flag setter must not expose input through parser errors")
		}
		if _, err := i.Read(func() ([]byte, error) { t.Fatal("invalid argument prompted"); return nil, nil }); !errors.Is(err, ErrInput) {
			t.Fatal("invalid argument fell back to environment")
		}
		i.Close()
	}
}

func TestFlagErrorsDefaultsAndDuplicateRefusalNeverContainPassword(t *testing.T) {
	for _, args := range [][]string{
		{"--vault-password=synthetic-argument", "--vault-password=synthetic-second"},
		{"--vault-password"},
		{"--vault-password=synthetic-argument", "--unknown"},
	} {
		i := New("synthetic-environment", true)
		var out bytes.Buffer
		flags := flag.NewFlagSet("fixture", flag.ContinueOnError)
		flags.SetOutput(&out)
		flags.Var(i, "vault-password", "Existing vault unlock password")
		err := flags.Parse(args)
		if err == nil {
			err = i.Validate()
		}
		if err == nil {
			t.Fatal("duplicate, missing or unknown option accepted")
		}
		flags.PrintDefaults()
		for _, secret := range []string{"synthetic-argument", "synthetic-second", "synthetic-environment"} {
			if strings.Contains(out.String(), secret) || strings.Contains(err.Error(), secret) || strings.Contains(i.String(), secret) {
				t.Fatal("parser error or defaults echoed a password")
			}
		}
		i.Close()
	}
}
