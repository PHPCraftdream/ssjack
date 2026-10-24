package ssjackui

import "embed"

// Files contains only the runtime plugin assets, not generated engine types.
//
//go:embed .claude-plugin/plugin.json hooks/hooks.json hooks/register.tsx hooks/format.ts
var Files embed.FS
