package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxInput = 1024 * 1024
const maxMessageRunes = 7000

type Event struct {
	ToolName     string                     `json:"tool_name"`
	ToolInput    map[string]json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage            `json:"tool_response"`
	Error        string                     `json:"error"`
}

type Output struct {
	SystemMessage string `json:"systemMessage,omitempty"`
}

func Run(action string, input []byte) ([]byte, error) {
	if len(input) > MaxInput {
		return nil, errors.New("hook input exceeds 1 MiB")
	}
	var event Event
	if json.Unmarshal(input, &event) != nil {
		return nil, errors.New("invalid Claude Code hook event")
	}
	var message string
	switch action {
	case "pre":
		if event.ToolName != "mcp__ssjack__remote_exec" {
			return json.Marshal(Output{})
		}
		target, err := stringField(event.ToolInput, "target")
		if err != nil {
			return nil, err
		}
		command, err := stringField(event.ToolInput, "command")
		if err != nil {
			return nil, err
		}
		message = fmt.Sprintf("ssjack -> %s\n$ %s", strconv.Quote(target), command)
	case "post":
		result := extract(event.ToolResponse)
		switch event.ToolName {
		case "mcp__ssjack__remote_exec":
			if result["isError"] == "true" || result["error"] != "" {
				message = "ssjack: command failed\n" + valueOr(result["error"], result["stdout"])
			} else if result["job_id"] != "" {
				message = "ssjack: started job " + result["job_id"]
			} else {
				message = "ssjack: command response\n" + result["stdout"]
			}
		case "mcp__ssjack__remote_read":
			message = formatRead(result)
		case "mcp__ssjack__remote_cancel":
			jobID, _ := stringField(event.ToolInput, "job_id")
			message = "ssjack: cancel job " + jobID + "\n" + valueOr(result["error"], valueOr(result["stdout"], "cancelled="+result["cancelled"]))
		default:
			return json.Marshal(Output{})
		}
	case "failure":
		if !strings.HasPrefix(event.ToolName, "mcp__ssjack__") {
			return json.Marshal(Output{})
		}
		message = fmt.Sprintf("ssjack: %s failed\n%s", event.ToolName, valueOr(event.Error, "No error details provided."))
	default:
		return nil, errors.New("expected hook pre, post, or failure")
	}
	return json.Marshal(Output{SystemMessage: truncate(printable(message), maxMessageRunes)})
}

func stringField(fields map[string]json.RawMessage, key string) (string, error) {
	var value string
	if json.Unmarshal(fields[key], &value) != nil || value == "" {
		return "", fmt.Errorf("hook event is missing string field %q", key)
	}
	return value, nil
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatRead(result map[string]string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "ssjack <- job %s", valueOr(result["job_id"], "unknown"))
	if done, ok := result["done"]; ok {
		fmt.Fprintf(&out, " | done=%s", done)
	}
	if code := result["exit_code"]; code != "" && code != "-1" {
		fmt.Fprintf(&out, " | exit=%s", code)
	}
	if result["stdout_lost"] == "true" || result["stderr_lost"] == "true" {
		out.WriteString("\nWARNING: some output was evicted.")
	}
	for _, stream := range []string{"stdout", "stderr"} {
		if binary := result[stream+"_base64"]; binary != "" {
			fmt.Fprintf(&out, "\n%s (base64):\n%s", stream, binary)
		} else if text := result[stream]; text != "" {
			fmt.Fprintf(&out, "\n%s:\n%s", stream, text)
		}
	}
	if result["error"] != "" {
		fmt.Fprintf(&out, "\nerror: %s", result["error"])
	}
	if result["isError"] == "true" {
		out.WriteString("\nTool reported an error.")
	}
	if result["stdout_more"] == "true" || result["stderr_more"] == "true" {
		out.WriteString("\nMore output is available.")
	}
	return out.String()
}

func extract(raw json.RawMessage) map[string]string {
	out := make(map[string]string)
	var walk func(json.RawMessage, int)
	walk = func(value json.RawMessage, depth int) {
		if depth > 8 || len(value) == 0 {
			return
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(value, &object) == nil && object != nil {
			for key, child := range object {
				switch key {
				case "job_id", "stdout", "stderr", "stdout_base64", "stderr_base64", "stdout_lost", "stderr_lost", "stdout_more", "stderr_more", "done", "exit_code", "cancelled", "error", "isError":
					var scalar any
					decoder := json.NewDecoder(strings.NewReader(string(child)))
					decoder.UseNumber()
					if decoder.Decode(&scalar) == nil {
						switch scalar.(type) {
						case string, bool, json.Number:
							out[key] = fmt.Sprint(scalar)
						}
					}
				case "text":
					var text string
					if json.Unmarshal(child, &text) == nil {
						if json.Valid([]byte(text)) {
							walk(json.RawMessage(text), depth+1)
						} else {
							out["stdout"] = text
						}
					}
				case "content", "structuredContent", "structured_content", "result", "data":
					walk(child, depth+1)
				}
			}
			return
		}
		var list []json.RawMessage
		if json.Unmarshal(value, &list) == nil {
			for _, item := range list {
				walk(item, depth+1)
			}
		}
	}
	walk(raw, 0)
	return out
}

func printable(message string) string {
	var out strings.Builder
	for _, r := range strings.ToValidUTF8(message, "\uFFFD") {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			out.WriteString(strconv.QuoteRuneToASCII(r))
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func truncate(message string, limit int) string {
	if utf8.RuneCountInString(message) <= limit {
		return message
	}
	return string([]rune(message)[:limit]) + "\n... output truncated"
}
