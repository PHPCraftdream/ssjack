package main

// Every tunable of the linter lives here; docs/LAYOUT.md describes the rules.

// Config holds the layout rules.
type Config struct {
	// CodeExtensions are lowercase extensions without the dot.
	CodeExtensions map[string]bool
	// ExcludedDirs are directory names skipped at any depth.
	// "fixtures" is deliberately absent: fixture code is code and is checked.
	ExcludedDirs map[string]bool
	// MaxFileLines is the per-file limit in physical lines (as wc -l).
	MaxFileLines int
	// MaxFilesPerDir is the limit of code files directly inside one folder.
	MaxFilesPerDir int
}

// DefaultConfig returns the repository rules.
func DefaultConfig() Config {
	return Config{
		CodeExtensions: set("go", "py", "ps1", "sh", "ts", "mts", "cts", "tsx", "js", "mjs", "cjs", "jsx", "rs"),
		ExcludedDirs:   set("node_modules", "dist", "vendor", "golden", "testdata"),
		MaxFileLines:   1000,
		MaxFilesPerDir: 7,
	}
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}
