package hooks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// RemoveDisplay removes only classic display hooks previously installed by ssjack.
func RemoveDisplay(root string) error {
	dir := filepath.Join(root, ".claude")
	if info, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid .claude directory; settings were not changed")
	}
	path := filepath.Join(dir, "settings.local.json")
	if info, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return errors.New("settings.local.json is not a regular file; settings were not changed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var settings map[string]json.RawMessage
	if len(data) > 2*1024*1024 || json.Unmarshal(data, &settings) != nil || settings == nil {
		return errors.New("invalid settings.local.json; file was not changed")
	}
	raw, ok := settings["hooks"]
	if !ok {
		return nil
	}
	var events map[string]json.RawMessage
	if json.Unmarshal(raw, &events) != nil || events == nil {
		return errors.New("invalid hooks object; settings were not changed")
	}
	changed := false
	for event, action := range map[string]string{"PreToolUse": "pre", "PostToolUse": "post", "PostToolUseFailure": "failure"} {
		raw, exists := events[event]
		if !exists {
			continue
		}
		var groups []json.RawMessage
		if json.Unmarshal(raw, &groups) != nil || groups == nil {
			return errors.New("invalid hook event; settings were not changed")
		}
		kept := make([]json.RawMessage, 0, len(groups))
		for _, rawGroup := range groups {
			var group map[string]json.RawMessage
			if json.Unmarshal(rawGroup, &group) != nil || group == nil {
				return errors.New("invalid hook group; settings were not changed")
			}
			var matcher string
			_ = json.Unmarshal(group["matcher"], &matcher)
			if !displayMatcher(event, matcher) {
				kept = append(kept, rawGroup)
				continue
			}
			var entries []json.RawMessage
			if json.Unmarshal(group["hooks"], &entries) != nil || entries == nil {
				return errors.New("invalid hook list; settings were not changed")
			}
			remaining := make([]json.RawMessage, 0, len(entries))
			removed := false
			for _, entry := range entries {
				var hook commandHook
				if json.Unmarshal(entry, &hook) == nil && ownedDisplay(hook, action) {
					removed = true
					continue
				}
				remaining = append(remaining, entry)
			}
			if !removed {
				kept = append(kept, rawGroup)
				continue
			}
			changed = true
			if len(remaining) == 0 {
				continue
			}
			group["hooks"], _ = json.Marshal(remaining)
			updated, _ := json.Marshal(group)
			kept = append(kept, updated)
		}
		if len(kept) == 0 {
			delete(events, event)
		} else {
			events[event], _ = json.Marshal(kept)
		}
	}
	if !changed {
		return nil
	}
	if len(events) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"], _ = json.Marshal(events)
	}
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return writeReplace(path, append(output, '\n'))
}

func displayMatcher(event, matcher string) bool {
	matcher = strings.TrimSuffix(strings.TrimPrefix(matcher, "^"), "$")
	switch event {
	case "PreToolUse":
		return matcher == "mcp__ssjack__remote_exec"
	case "PostToolUse":
		return matcher == "mcp__ssjack__(remote_exec|remote_read|remote_cancel)"
	case "PostToolUseFailure":
		return matcher == "mcp__ssjack__.*"
	default:
		return false
	}
}

func ownedDisplay(hook commandHook, action string) bool {
	if hook.Type != "command" || len(hook.Args) != 2 || hook.Args[0] != "hook" || hook.Args[1] != action {
		return false
	}
	name := strings.ToLower(filepath.Base(hook.Command))
	return name == "ssjack" || name == "ssjack.exe" || name == "ssjack-next.exe"
}
