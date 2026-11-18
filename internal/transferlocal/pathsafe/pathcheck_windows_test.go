//go:build windows

package pathsafe

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/localtest"
)

func TestValidateLocalRelPathWindowsValid(t *testing.T) {
	valid := []string{
		"file.txt",
		"dir/file.txt",
		"данные файл.txt",
		"with space.txt",
		"..hidden",
		"a.b.c",
		"null.txt",
		"COM10",
	}
	for _, p := range valid {
		if err := ValidateLocalRelPath(p, transfercore.DefaultLimits()); err != nil {
			t.Errorf("ValidateLocalRelPath(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateLocalRelPathWindowsRefused(t *testing.T) {
	dir := "tempdir"
	refused := []string{
		"",
		"/abs",
		"a/../b",
		"a//b",
		`a\b`,
		"a:b",
		"a\x01b",
		"a\x7fb",
		"x.",
		"x ",
		"CON",
		"con",
		"Con.txt",
		"NUL.tar.gz",
		"PRN",
		"AUX",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"com3.txt",
	}
	for _, p := range refused {
		t.Run(p, func(t *testing.T) {
			err := ValidateLocalRelPath(p, transfercore.DefaultLimits())
			localtest.RequireClass(t, err, transfercore.ClassRefusedPath, dir)
		})
	}
	limits := transfercore.DefaultLimits()
	t.Run("too deep", func(t *testing.T) {
		deep := strings.Repeat("a/", limits.MaxDepth+1) + "x"
		localtest.RequireClass(t, ValidateLocalRelPath(deep, limits), transfercore.ClassRefusedPath, dir)
	})
	t.Run("too long", func(t *testing.T) {
		long := strings.Repeat("a", limits.MaxPathBytes+1)
		localtest.RequireClass(t, ValidateLocalRelPath(long, limits), transfercore.ClassRefusedPath, dir)
	})
}

func TestValidateLocalComponentWindows(t *testing.T) {
	if err := validateLocalComponent(""); err == nil {
		t.Fatal("validateLocalComponent(\"\") = nil, want error")
	}
	if err := validateLocalComponent(".."); err == nil {
		t.Fatal(`validateLocalComponent("..") = nil, want error`)
	}
}

func TestReservedDeviceBaseFirstDot(t *testing.T) {
	if !reservedDeviceName("nul.txt.x") {
		t.Fatal("reservedDeviceName(\"nul.txt.x\") = false, want true (base is up to first dot)")
	}
	if reservedDeviceName("null.txt") {
		t.Fatal("reservedDeviceName(\"null.txt\") = true, want false")
	}
}
