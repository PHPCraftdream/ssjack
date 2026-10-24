package hooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type commandHook struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

func Install(root, executable string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, ".claude")
	if info, err := os.Lstat(dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New(".claude is a symlink; settings were not changed")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "settings.local.json")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("settings.local.json is not a regular file; settings were not changed")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	original, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	settings := make(map[string]json.RawMessage)
	if len(original) > 0 {
		if len(original) > 2*1024*1024 || json.Unmarshal(original, &settings) != nil || settings == nil {
			return errors.New("invalid settings.local.json; file was not changed")
		}
	} else if err == nil {
		return errors.New("empty settings.local.json; file was not changed")
	}
	events := make(map[string]json.RawMessage)
	if raw, ok := settings["hooks"]; ok {
		if json.Unmarshal(raw, &events) != nil || events == nil {
			return errors.New("invalid hooks object; file was not changed")
		}
	}
	for _, rule := range []struct{ event, matcher, action string }{
		{"PreToolUse", "^mcp__ssjack__remote_exec$", "pre"},
		{"PostToolUse", "^mcp__ssjack__(remote_exec|remote_read|remote_cancel)$", "post"},
		{"PostToolUseFailure", "^mcp__ssjack__.*$", "failure"},
	} {
		updated, err := mergeEvent(events[rule.event], rule.matcher, executable, rule.action)
		if err != nil {
			return fmt.Errorf("invalid %s hooks; settings were not changed: %w", rule.event, err)
		}
		events[rule.event] = updated
	}
	settings["hooks"], err = json.Marshal(events)
	if err != nil {
		return err
	}
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	output = append(output, '\n')
	if bytes.Equal(output, original) {
		return nil
	}
	return writeReplace(path, output)
}

func mergeEvent(raw json.RawMessage, matcher, executable, action string) (json.RawMessage, error) {
	var groups []json.RawMessage
	if len(raw) > 0 && (json.Unmarshal(raw, &groups) != nil || groups == nil) {
		return nil, errors.New("event must be an array")
	}
	for i, item := range groups {
		var group map[string]json.RawMessage
		if json.Unmarshal(item, &group) != nil || group == nil {
			return nil, errors.New("hook group must be an object")
		}
		var existing string
		_ = json.Unmarshal(group["matcher"], &existing)
		if existing != matcher {
			continue
		}
		var entries []json.RawMessage
		if json.Unmarshal(group["hooks"], &entries) != nil || entries == nil {
			return nil, errors.New("hooks must be an array")
		}
		entries, err := mergeHook(entries, executable, action)
		if err != nil {
			return nil, err
		}
		group["hooks"], _ = json.Marshal(entries)
		groups[i], _ = json.Marshal(group)
		return json.Marshal(groups)
	}
	entries, err := mergeHook(nil, executable, action)
	if err != nil {
		return nil, err
	}
	group, err := json.Marshal(map[string]any{"matcher": matcher, "hooks": entries})
	if err != nil {
		return nil, err
	}
	return json.Marshal(append(groups, group))
}

func mergeHook(entries []json.RawMessage, executable, action string) ([]json.RawMessage, error) {
	for i, raw := range entries {
		var hook commandHook
		if json.Unmarshal(raw, &hook) != nil || hook.Type != "command" || len(hook.Args) != 2 || hook.Args[0] != "hook" || hook.Args[1] != action || !strings.HasPrefix(strings.ToLower(filepath.Base(hook.Command)), "ssjack") {
			continue
		}
		if hook.Command == executable {
			return entries, nil
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, err
		}
		object["command"], _ = json.Marshal(executable)
		updated, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		entries[i] = updated
		return entries, nil
	}
	entry, err := json.Marshal(commandHook{Type: "command", Command: executable, Args: []string{"hook", action}, Timeout: 5})
	if err != nil {
		return nil, err
	}
	return append(entries, entry), nil
}

func writeReplace(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ssjack-settings-*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
