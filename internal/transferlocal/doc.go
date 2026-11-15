// Package transferlocal implements the local filesystem safety layer of the
// file transfer engine (docs/FILE-TRANSFER.md): owner-registered roots,
// no-follow path resolution, staging with atomic publication and safe archive
// extraction.
//
// Every error returned to callers is a *transfercore.Error with a fixed,
// content-free message: no local paths, no file content and no underlying OS
// error text. Behaviour is uniform on Linux, macOS and Windows with
// platform-specific code confined to *_unix.go and *_windows.go files.
//
// There is no context plumbing: callers cancel by closing streams and clean
// staging via Abort.
package transferlocal
