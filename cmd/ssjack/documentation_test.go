package main

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCurrentOperatorDocumentationLinksResolve(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	links := regexp.MustCompile(`\[[^\]]*\]\(([^\s()]+)\)`)
	for _, name := range []string{
		"README.md", "SSJACK.md", "docs/README.md", "docs/VAULT.md", "docs/INSTALL.md",
		"docs/application-store/NAMED-DIRECTORY.md", "docs/application-store/TEXT-ADAPTER.md",
		"docs/application-store/TEXT-REVERSE-COPY.md", "docs/application-store/TEXT-STREAMING.md",
		"docs/application-store/TEXT-STREAM-HTTP.md", "docs/declarative/README.md",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range links.FindAllSubmatch(data, -1) {
			link := string(match[1])
			parsed, err := url.Parse(link)
			if err != nil {
				t.Fatalf("%s has an invalid documentation link: %s", name, link)
			}
			if parsed.IsAbs() || parsed.Host != "" || parsed.Path == "" {
				continue
			}
			target := filepath.Join(filepath.Dir(path), filepath.FromSlash(parsed.Path))
			relative, err := filepath.Rel(root, target)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				t.Fatalf("%s links outside the checkout: %s", name, link)
			}
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("%s has an unresolved local link %s: %v", name, link, err)
			}
		}
	}
}
