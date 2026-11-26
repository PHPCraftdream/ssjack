package discovery

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/application"
)

const (
	maxEntries              = 256
	maxCandidates           = 16
	maxDiagnostics          = 16
	maxCollectedDiagnostics = maxEntries + 2
	maxDescriptor           = 16 * 1024
)

type Candidate struct {
	Path          string
	Name          string
	Collision     bool
	Buffer        []byte
	Fingerprint   [32]byte
	CanonicalPath string
	Identity      os.FileInfo
}

type Diagnostic struct {
	Path   string
	Reason string
}

type Result struct {
	Candidates  []Candidate
	Diagnostics []Diagnostic
	// Undescribed lists scanned folders (root as ".") without a descriptor:
	// not candidates and not rejections, so they never become Diagnostics.
	Undescribed    []string
	Overflow       bool
	OverflowReason string
}

var ignored = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true,
	"vendor": true, "target": true, "dist": true, "build": true,
	".cache": true, ".next": true, ".venv": true, "venv": true,
	"__pycache__": true,
}

func openRootGuarded(path string) (root *os.Root, rootDir *os.File, rootPath string, rootInfo os.FileInfo, reason string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, "", nil, "root_unavailable"
	}
	rootPath = filepath.Clean(abs)
	resolved, err := resolveRoot(rootPath)
	if err != nil {
		return nil, nil, "", nil, "root_inaccessible"
	}
	rootPath = filepath.Clean(resolved)
	initial, err := os.Lstat(rootPath)
	if err != nil || !initial.IsDir() || isReparse(initial) {
		return nil, nil, "", nil, "root_unsafe"
	}
	root, err = os.OpenRoot(rootPath)
	if err != nil {
		return nil, nil, "", nil, "root_inaccessible"
	}
	rootDir, err = root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, "", nil, "root_unsafe"
	}
	rootInfo, err = rootDir.Stat()
	if err != nil || !rootInfo.IsDir() || !os.SameFile(initial, rootInfo) || handleIsReparse(rootDir) {
		_ = rootDir.Close()
		_ = root.Close()
		return nil, nil, "", nil, "root_unsafe"
	}
	return root, rootDir, rootPath, rootInfo, ""
}

func Scan(rootPath string) Result {
	result := Result{Candidates: []Candidate{}, Diagnostics: []Diagnostic{}}
	root, rootDir, rootPath, rootInfo, reason := openRootGuarded(rootPath)
	if reason != "" {
		addDiagnostic(&result, ".", reason)
		finish(&result)
		return result
	}
	defer root.Close()
	defer rootDir.Close()
	seen := []directoryIdentity{}
	addCandidateFromRoot(&result, rootPath, root, rootInfo, ".", &seen, nil)

	entries, fallbackDescriptor, overflow, readErr := readEntries(root, rootDir)
	if overflow {
		result.Overflow, result.OverflowReason, result.Candidates = true, "entry_cap_overflow", nil
		return finalizeScan(rootPath, rootInfo, &result)
	}
	if readErr != nil {
		result.Candidates = nil
		addDiagnostic(&result, ".", "root_inaccessible")
		return finalizeScan(rootPath, rootInfo, &result)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		base := entry.Name()
		if base == application.DescriptorFile || base == fallbackDescriptor {
			continue
		}
		if !safeText(base) {
			addDiagnostic(&result, "", "path_unsafe")
			continue
		}
		if ignoredBasename(base) {
			continue
		}
		rel := filepath.ToSlash(base)
		info, err := root.Lstat(base)
		if err != nil {
			addDiagnostic(&result, rel, "entry_inaccessible")
			continue
		}
		if isReparse(info) || info.Mode()&os.ModeSymlink != 0 {
			addDiagnostic(&result, rel, "entry_unsafe")
			continue
		}
		if !info.IsDir() {
			continue
		}
		childRoot, err := root.OpenRoot(base)
		if err != nil {
			addDiagnostic(&result, rel, "entry_unsafe")
			continue
		}
		childDir, err := childRoot.Open(".")
		if err != nil {
			_ = childRoot.Close()
			addDiagnostic(&result, rel, "entry_unsafe")
			continue
		}
		identity, statErr := childDir.Stat()
		unsafe := statErr != nil || !identity.IsDir() || !os.SameFile(info, identity) || handleIsReparse(childDir)
		_ = childDir.Close()
		if unsafe {
			_ = childRoot.Close()
			addDiagnostic(&result, rel, "entry_unsafe")
			continue
		}
		addCandidateFromRoot(&result, rootPath, childRoot, identity, rel, &seen, func() bool {
			current, currentErr := root.Lstat(base)
			return currentErr == nil && current.IsDir() && !isReparse(current) && os.SameFile(identity, current)
		})
		_ = childRoot.Close()
		if result.Overflow {
			result.Candidates = nil
			return finalizeScan(rootPath, rootInfo, &result)
		}
	}
	return finalizeScan(rootPath, rootInfo, &result)
}

func finalizeScan(path string, identity os.FileInfo, result *Result) Result {
	if !rootPathStillMatches(path, identity) {
		result.Candidates = nil
		addDiagnostic(result, ".", "root_changed")
	}
	finish(result)
	return *result
}

func rootPathStillMatches(path string, identity os.FileInfo) bool {
	current, err := os.Lstat(path)
	return err == nil && current.IsDir() && !isReparse(current) && current.Mode()&os.ModeSymlink == 0 && os.SameFile(identity, current)
}

func readEntries(root *os.Root, rootDir *os.File) ([]os.DirEntry, string, bool, error) {
	entries := make([]os.DirEntry, 0, maxEntries+1)
	count := 0
	var pendingFolded os.DirEntry
	var descriptorInfo os.FileInfo
	var descriptorErr error
	if runtime.GOOS == "windows" {
		descriptorInfo, descriptorErr = root.Lstat(application.DescriptorFile)
	}
	exactFound := false
	foldedExempt := false
	for {
		batch, err := rootDir.ReadDir(64)
		for _, entry := range batch {
			name := entry.Name()
			if name == application.DescriptorFile {
				exactFound = true
				if pendingFolded != nil {
					entries = append(entries, pendingFolded)
					count++
					pendingFolded = nil
					if count > maxEntries {
						return nil, "", true, nil
					}
				}
				continue
			}
			if runtime.GOOS == "windows" && !exactFound && !foldedExempt && isFoldedDescriptorName(name) && descriptorErr == nil {
				entryInfo, infoErr := entry.Info()
				if infoErr == nil && os.SameFile(descriptorInfo, entryInfo) {
					foldedExempt = true
					pendingFolded = entry
					continue
				}
			}
			entries = append(entries, entry)
			count++
			if count > maxEntries {
				return nil, "", true, nil
			}
		}
		if err == io.EOF {
			fallback := ""
			if pendingFolded != nil {
				fallback = pendingFolded.Name()
			}
			return entries, fallback, false, nil
		}
		if err != nil {
			return nil, "", false, err
		}
		if len(batch) == 0 {
			return entries, "", false, nil
		}
	}
}

type directoryIdentity struct {
	info os.FileInfo
}

func readValidatedDescriptor(root *os.Root) (data []byte, name string, digest [32]byte, reason string) {
	data, reason = readBoundedDescriptor(root)
	if reason != "" {
		return nil, "", [32]byte{}, reason
	}
	name, err := application.ValidateDiscoveryDescriptor(data)
	if err != nil {
		return data, "", [32]byte{}, "descriptor_invalid"
	}
	digest, ok := descriptorFingerprint(data)
	if !ok {
		return data, name, [32]byte{}, "fingerprint_unavailable"
	}
	return data, name, digest, ""
}

func addCandidateFromRoot(result *Result, canonicalRoot string, directory *os.Root, identity os.FileInfo, rel string, seen *[]directoryIdentity, validate func() bool) {
	data, name, digest, reason := readValidatedDescriptor(directory)
	if reason == "descriptor_missing" {
		result.Undescribed = append(result.Undescribed, normalizedDiagnosticPath(rel))
		return
	}
	if reason != "" {
		addDiagnostic(result, rel, reason)
		return
	}
	if validate != nil && !validate() {
		addDiagnostic(result, rel, "entry_unsafe")
		return
	}
	for _, previous := range *seen {
		if os.SameFile(previous.info, identity) {
			return
		}
	}
	if len(result.Candidates) == maxCandidates {
		result.Overflow, result.OverflowReason = true, "candidate_cap_overflow"
		result.Candidates = nil
		return
	}
	*seen = append(*seen, directoryIdentity{info: identity})
	result.Candidates = append(result.Candidates, Candidate{Path: normalizedDiagnosticPath(rel), Name: name, Buffer: data, Fingerprint: digest, CanonicalPath: canonicalCandidatePath(canonicalRoot, rel), Identity: identity})
}

func canonicalCandidatePath(root, rel string) string {
	if rel == "." {
		return filepath.Clean(root)
	}
	return filepath.Join(root, filepath.FromSlash(rel))
}

func readBoundedDescriptor(root *os.Root) ([]byte, string) {
	info, err := root.Lstat(application.DescriptorFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "descriptor_missing"
		}
		return nil, "descriptor_inaccessible"
	}
	if isReparse(info) || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, "descriptor_unsafe"
	}
	if info.Size() > maxDescriptor {
		return nil, "descriptor_oversize"
	}
	file, err := root.Open(application.DescriptorFile)
	if err != nil {
		return nil, "descriptor_inaccessible"
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || handleIsReparse(file) {
		return nil, "descriptor_unsafe"
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDescriptor+1))
	if err != nil {
		return nil, "descriptor_inaccessible"
	}
	if len(data) > maxDescriptor {
		return nil, "descriptor_oversize"
	}
	return data, ""
}

func addDiagnostic(result *Result, path, reason string) {
	if len(result.Diagnostics) >= maxCollectedDiagnostics {
		return
	}
	result.Diagnostics = append(result.Diagnostics, Diagnostic{Path: normalizedDiagnosticPath(path), Reason: reason})
}

func normalizedDiagnosticPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(path))
}

func diagnosticLess(a, b Diagnostic) bool {
	if a.Path == "." {
		return b.Path != "."
	}
	if b.Path == "." {
		return false
	}
	if a.Path < b.Path {
		return true
	}
	if a.Path > b.Path {
		return false
	}
	return a.Reason < b.Reason
}

func finish(result *Result) {
	sort.Strings(result.Undescribed)
	sort.Slice(result.Candidates, func(i, j int) bool {
		a, b := normalizedDiagnosticPath(result.Candidates[i].Path), normalizedDiagnosticPath(result.Candidates[j].Path)
		if a == "." {
			return b != "."
		}
		if b == "." {
			return false
		}
		return a < b
	})
	counts := map[string]int{}
	for _, c := range result.Candidates {
		counts[c.Name]++
	}
	for i := range result.Candidates {
		result.Candidates[i].Collision = counts[result.Candidates[i].Name] > 1
	}
	diagnostics := result.Diagnostics[:0]
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Reason != "additional_rejections" {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	result.Diagnostics = diagnostics
	sort.Slice(result.Diagnostics, func(i, j int) bool { return diagnosticLess(result.Diagnostics[i], result.Diagnostics[j]) })
	if len(result.Diagnostics) > maxDiagnostics {
		result.Diagnostics = result.Diagnostics[:maxDiagnostics]
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Reason: "additional_rejections"})
	}
}

func isFoldedDescriptorName(name string) bool {
	return strings.EqualFold(name, application.DescriptorFile)
}

func ignoredBasename(name string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		name = strings.ToLower(name)
	}
	return ignored[name]
}

func safeText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
