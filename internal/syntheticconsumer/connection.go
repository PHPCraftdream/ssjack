package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	envLaunch   = "SSJACK_TEXT_LAUNCH"
	envProfile  = "SSJACK_TEXT_PROFILE"
	envEndpoint = "SSJACK_APP_ENDPOINT"
	envToken    = "SSJACK_APP_TOKEN"
	envPin      = "SSJACK_APP_CERTIFICATE_SHA256"

	mcpPath     = "/mcp"
	preparePath = "/text-stream-v2/prepare"
	executePath = "/text-stream-v2/execute"
	reversePath = "/text-stream-v2/reverse-copy"

	streamFormat      = "ssjack-text-stream-v2"
	streamContentType = "application/x-ndjson"

	hydrateLimit      = 32 << 10
	copyLimit         = 1 << 20
	hydrateReplyLimit = 64 << 10
	copyReplyLimit    = (24 << 20) + (64 << 10)
	streamReplyLimit  = 4 << 10
	referencesLimit   = 64 << 10
	maxReferences     = 16
	maxReferenceBytes = 1024
)

// connection is the pinned, bearer-authenticated channel to the adapter
// context that the launcher exposed through the child environment.
type connection struct {
	endpoint url.URL
	token    string
	client   *http.Client
}

// connect accepts only a launcher-provided context whose expected profile
// equals the requested one. It never falls back to ambient configuration.
func connect(profile string) (*connection, bool) {
	if os.Getenv(envLaunch) != "1" || profile == "" || os.Getenv(envProfile) != profile {
		return nil, false
	}
	target, err := url.Parse(os.Getenv(envEndpoint))
	token := os.Getenv(envToken)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.Path != mcpPath || target.RawQuery != "" || target.User != nil || token == "" {
		return nil, false
	}
	config, err := wire.ClientTLS(os.Getenv(envPin))
	if err != nil {
		return nil, false
	}
	return &connection{endpoint: *target, token: token, client: &http.Client{
		Transport:     &http.Transport{TLSClientConfig: config},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, true
}

func (c *connection) request(ctx context.Context, path, contentType string, body io.Reader) (*http.Request, error) {
	target := c.endpoint
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", contentType)
	return request, nil
}

type toolResult struct {
	status string
	text   *string
}

// tool performs one bounded JSON-RPC tool call. Any transport, envelope or
// shape irregularity is reported as not ok, which callers treat as unknown.
func (c *connection) tool(ctx context.Context, name string, arguments any, limit int64) (toolResult, bool) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": arguments},
	})
	if err != nil {
		return toolResult{}, false
	}
	request, err := c.request(ctx, mcpPath, "application/json", bytes.NewReader(body))
	if err != nil {
		return toolResult{}, false
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-06-18")
	response, err := c.client.Do(request)
	if err != nil {
		return toolResult{}, false
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit || response.StatusCode != http.StatusOK {
		return toolResult{}, false
	}
	var reply struct {
		ID     json.RawMessage  `json:"id"`
		Error  *json.RawMessage `json:"error"`
		Result *struct {
			IsError           bool `json:"isError"`
			StructuredContent *struct {
				Status string  `json:"status"`
				Text   *string `json:"text"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &reply) != nil || string(bytes.TrimSpace(reply.ID)) != "1" || reply.Error != nil || reply.Result == nil || reply.Result.IsError || reply.Result.StructuredContent == nil {
		return toolResult{}, false
	}
	return toolResult{status: reply.Result.StructuredContent.Status, text: reply.Result.StructuredContent.Text}, true
}

type streamHeader struct {
	Format      string   `json:"format"`
	OperationID string   `json:"operation_id"`
	Profile     string   `json:"profile"`
	File        string   `json:"file"`
	References  []string `json:"references"`
	Ticket      string   `json:"ticket,omitempty"`
}

type streamReply struct {
	Format      string `json:"format"`
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	Ticket      string `json:"ticket,omitempty"`
}

// line encodes the header as one newline-terminated JSON record.
func (h streamHeader) line() ([]byte, bool) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(h) != nil {
		return nil, false
	}
	return buffer.Bytes(), true
}

// readReply parses a small JSON metadata reply and checks its correlation.
func readReply(response *http.Response, id string) (streamReply, bool) {
	kind, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" || response.StatusCode != http.StatusOK {
		return streamReply{}, false
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, streamReplyLimit+1))
	var reply streamReply
	if err != nil || len(data) > streamReplyLimit || json.Unmarshal(data, &reply) != nil {
		return streamReply{}, false
	}
	if reply.Format != streamFormat || reply.OperationID != id {
		return streamReply{}, false
	}
	return reply, true
}

func operationID() (string, bool) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), true
}

func canonicalID(id string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(raw) == 16 && base64.RawURLEncoding.EncodeToString(raw) == id
}

// readText loads a bounded UTF-8 text file without NUL bytes.
func readText(path string, limit int64) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return "", false
	}
	return string(data), true
}

// readReferences loads the bounded JSON array of exact canonical references.
func readReferences(path string) ([]string, bool) {
	text, ok := readText(path, referencesLimit)
	if !ok {
		return nil, false
	}
	var references []string
	if json.Unmarshal([]byte(text), &references) != nil || len(references) == 0 || len(references) > maxReferences {
		return nil, false
	}
	for _, reference := range references {
		if reference == "" || len(reference) > maxReferenceBytes {
			return nil, false
		}
	}
	return references, true
}
