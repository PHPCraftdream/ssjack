package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
)

const remoteMCPRegistrationBudget = 15 * time.Second
const maxRemoteMCPActiveCalls = 4
const maxRemoteMCPCalls = 4096
const maxRemoteMCPTools = mcpchannel.MaxChannels * mcpbridge.MaxInventoryTools

type remoteMCPRegistration struct {
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	mu          sync.Mutex
	clients     []*mcpchannel.Client
	closing     bool
	active      int
	messages    int
	activeDone  chan struct{}
	cleanupOnce sync.Once
	cleanupDone chan struct{}
}

type remoteInventory struct {
	client  *mcpchannel.Client
	ordinal int
	tools   []mcp.Tool
}

func startRemoteMCPRegistration(parent context.Context, descriptors []mcpchannel.Descriptor, server *mcp.Server) *remoteMCPRegistration {
	deadline := time.Now().Add(mcpchannel.RuntimeLease)
	for _, descriptor := range descriptors {
		expires := time.Unix(descriptor.ExpiresUnix, 0)
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	registration := &remoteMCPRegistration{ctx: ctx, cancel: cancel, done: make(chan struct{}), activeDone: closedRegistrationSignal(), cleanupDone: make(chan struct{})}
	context.AfterFunc(ctx, func() { registration.cleanupOnce.Do(func() { go registration.cleanup() }) })
	go func() {
		defer close(registration.done)
		registration.register(ctx, descriptors, server)
	}()
	return registration
}

func closedRegistrationSignal() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (r *remoteMCPRegistration) beginCall() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.ctx.Err() != nil || r.active >= maxRemoteMCPActiveCalls || r.messages >= maxRemoteMCPCalls {
		return false
	}
	if r.active == 0 {
		r.activeDone = make(chan struct{})
	}
	r.active++
	r.messages++
	return true
}

func (r *remoteMCPRegistration) endCall() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active--
	if r.active == 0 {
		close(r.activeDone)
	}
}

func (r *remoteMCPRegistration) retain(client *mcpchannel.Client) bool {
	r.mu.Lock()
	if r.closing || r.ctx.Err() != nil {
		r.mu.Unlock()
		client.Close()
		return false
	}
	r.clients = append(r.clients, client)
	r.mu.Unlock()
	return true
}

func (r *remoteMCPRegistration) Close(ctx context.Context) error {
	if ctx == nil {
		return mcpchannel.ErrCleanup
	}
	r.cleanupOnce.Do(func() { go r.cleanup() })
	select {
	case <-r.cleanupDone:
		return nil
	case <-ctx.Done():
		return mcpchannel.ErrCleanup
	}
}

func (r *remoteMCPRegistration) cleanup() {
	r.cancel()
	r.mu.Lock()
	r.closing = true
	clients := append([]*mcpchannel.Client(nil), r.clients...)
	activeDone := r.activeDone
	r.mu.Unlock()
	for _, client := range clients {
		client.Close()
	}
	<-r.done
	<-activeDone
	close(r.cleanupDone)
}

func (r *remoteMCPRegistration) register(ctx context.Context, descriptors []mcpchannel.Descriptor, server *mcp.Server) {
	results := make(chan remoteInventory, len(descriptors))
	semaphore := make(chan struct{}, 4)
	var workers sync.WaitGroup
	for _, descriptor := range descriptors {
		descriptor := descriptor
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- remoteInventory{}
				return
			}
			operation, cancel := context.WithTimeout(ctx, mcpchannel.OperationBudget)
			defer cancel()
			client, err := mcpchannel.Connect(operation, descriptor)
			if client == nil || err != nil {
				if client != nil {
					client.Close()
				}
				results <- remoteInventory{}
				return
			}
			if !r.retain(client) {
				results <- remoteInventory{}
				return
			}
			data, err := client.Describe(operation)
			if err != nil {
				results <- remoteInventory{}
				return
			}
			tools, err := decodeRemoteInventory(data, descriptor.Ordinal)
			if err != nil {
				results <- remoteInventory{}
				return
			}
			results <- remoteInventory{client: client, ordinal: descriptor.Ordinal, tools: tools}
		}()
	}
	workers.Wait()
	close(results)
	if ctx.Err() != nil {
		return
	}
	failed := false
	all := make([]remoteInventory, 0, len(descriptors))
	for inventory := range results {
		if inventory.client == nil {
			failed = true
			continue
		}
		all = append(all, inventory)
	}
	if ctx.Err() != nil {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ordinal < all[j].ordinal })
	seen := map[string]bool{}
	count := 0
	for _, inventory := range all {
		valid := len(inventory.tools) <= mcpbridge.MaxInventoryTools && count+len(inventory.tools) <= maxRemoteMCPTools
		local := make(map[string]bool, len(inventory.tools))
		for _, tool := range inventory.tools {
			if seen[tool.Name] || local[tool.Name] {
				valid, failed = false, true
				break
			}
			local[tool.Name] = true
		}
		if !valid {
			continue
		}
		for _, tool := range inventory.tools {
			seen[tool.Name] = true
			toolCopy := tool
			server.AddTool(&toolCopy, remoteMCPTool(r, inventory.client, tool.Name))
		}
		count += len(inventory.tools)
	}
	if failed {
		fmt.Fprintln(os.Stderr, "Some remote MCP connections are unavailable for this session.")
	}
}

type remoteInventoryTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"schema"`
}

type remoteInventoryOutput struct {
	Ordinal int                   `json:"ordinal"`
	Tools   []remoteInventoryTool `json:"tools"`
}

func decodeRemoteInventory(data []byte, ordinal int) ([]mcp.Tool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var inventory remoteInventoryOutput
	if err := decoder.Decode(&inventory); err != nil || inventory.Ordinal != ordinal || len(inventory.Tools) == 0 || len(inventory.Tools) > mcpbridge.MaxInventoryTools {
		return nil, mcpchannel.ErrClient
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, mcpchannel.ErrClient
	}
	tools := make([]mcp.Tool, 0, len(inventory.Tools))
	seen := map[string]bool{}
	for _, item := range inventory.Tools {
		encoded, err := json.Marshal(item.Schema)
		if err != nil || len(encoded) > mcpbridge.MaxSchemaBytes || item.Name == "" || len(item.Name) > 64 || len(item.Description) > mcpbridge.MaxToolDescription || !remoteMCPToolName(item.Name) || item.Schema == nil || item.Schema["type"] != "object" || seen[item.Name] {
			return nil, mcpchannel.ErrClient
		}
		seen[item.Name] = true
		tools = append(tools, mcp.Tool{Name: item.Name, Description: item.Description, InputSchema: item.Schema})
	}
	return tools, nil
}

var remoteMCPToolPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func remoteMCPToolName(name string) bool { return remoteMCPToolPattern.MatchString(name) }
