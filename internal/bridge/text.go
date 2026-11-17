package bridge

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Every tool of this package answers with exactly one plain-text content
// block. The tools are registered through the SDK's typed AddTool with the
// output type any: the SDK then derives no output schema and, because the
// handler returns a nil output value, sets no structured content and writes no
// JSON text block. The handler supplies the finished CallToolResult itself.

// fieldSep separates fields grouped on one line of a result.
const fieldSep = " · "

// noText is the error text of a failure that carries no message.
const noText = "tool call failed"

// addTextTool registers a tool whose result is plain text only; handle
// produces the text of one successful call.
func addTextTool[In any](server *mcp.Server, tool *mcp.Tool, handle func(ctx context.Context, input In) (string, error)) {
	mcp.AddTool[In, any](server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, input In) (*mcp.CallToolResult, any, error) {
		text, err := handle(ctx, input)
		return textResult(text, err), nil, nil
	})
}

// textResult is the single-text-block result of a call. A failure keeps its
// message verbatim as the text, with IsError set.
func textResult(text string, err error) *mcp.CallToolResult {
	if err == nil {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
	}
	message := err.Error()
	if message == "" {
		message = noText
	}
	result := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: message}}}
	result.SetError(err)
	return result
}

// ResultText returns the text of a tool result of this package: exactly one
// text content block and no structured content.
func ResultText(result *mcp.CallToolResult) (string, error) {
	if result == nil {
		return "", errors.New("tool result is missing")
	}
	if result.StructuredContent != nil {
		return "", errors.New("tool result carries structured content")
	}
	if len(result.Content) != 1 {
		return "", errors.New("tool result does not have exactly one content block")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		return "", errors.New("tool result content is not text")
	}
	return text.Text, nil
}

// joinFields joins the non-empty fields of one line.
func joinFields(fields ...string) string {
	kept := make([]string, 0, len(fields))
	for _, field := range fields {
		if field != "" {
			kept = append(kept, field)
		}
	}
	return strings.Join(kept, fieldSep)
}

// oneLine folds line breaks of a message into spaces so that it stays on one
// line of a result.
func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// groupInt formats an integer with thousands separators.
func groupInt(n int64) string {
	digits := strconv.FormatInt(n, 10)
	sign := ""
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	var out strings.Builder
	for i, digit := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(digit)
	}
	return sign + out.String()
}

// parseGrouped reads an integer written by groupInt.
func parseGrouped(text string) (int64, error) {
	return strconv.ParseInt(strings.ReplaceAll(text, ",", ""), 10, 64)
}

// yesNo spells a flag in the Next lines.
func yesNo(flag bool) string {
	if flag {
		return "yes"
	}
	return "no"
}
