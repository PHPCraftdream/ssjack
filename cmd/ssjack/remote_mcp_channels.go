package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpjson"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func prepareMCPBootstrapOutput(ctx context.Context, known remote.GuardProvider, runtime *mcpbridge.Runtime) (remote.GuardProvider, func(*outputguard.Snapshot) error) {
	var mu sync.RWMutex
	var mandatory *outputguard.Snapshot
	attempted := false
	setup := func(snapshot *outputguard.Snapshot) error {
		mu.Lock()
		defer mu.Unlock()
		if attempted {
			return mcpchannel.ErrSetup
		}
		attempted = true
		if snapshot == nil || known == nil || ctx == nil || ctx.Err() != nil {
			return mcpchannel.ErrSetup
		}
		knownSnapshot, err := known(ctx)
		if err != nil || knownSnapshot == nil {
			return mcpchannel.ErrSetup
		}
		if _, err := outputguard.Union(knownSnapshot, snapshot); err != nil || ctx.Err() != nil {
			return mcpchannel.ErrSetup
		}
		if runtime != nil && runtime.ConfigureOutput(knownSnapshot, snapshot) != nil {
			return mcpchannel.ErrSetup
		}
		if ctx.Err() != nil {
			return mcpchannel.ErrSetup
		}
		mandatory = snapshot
		return nil
	}
	provider := func(ctx context.Context) (*outputguard.Snapshot, error) {
		if ctx == nil || ctx.Err() != nil || known == nil {
			return nil, outputguard.ErrGuard
		}
		knownSnapshot, err := known(ctx)
		if err != nil || knownSnapshot == nil {
			return nil, outputguard.ErrGuard
		}
		mu.RLock()
		tokenSnapshot := mandatory
		mu.RUnlock()
		if tokenSnapshot == nil {
			return nil, outputguard.ErrGuard
		}
		combined, err := outputguard.Union(knownSnapshot, tokenSnapshot)
		if err != nil || ctx.Err() != nil {
			return nil, outputguard.ErrGuard
		}
		return combined, nil
	}
	return provider, setup
}

func prepareRemoteMCPChannels(ctx context.Context, credentials *agentCredentials, known remote.GuardProvider, ttl time.Duration) (remote.GuardProvider, string, error) {
	if credentials == nil || credentials.mcpBridge == nil {
		return known, "", nil
	}
	if ctx == nil || known == nil {
		return nil, "", mcpchannel.ErrSetup
	}
	knownSnapshot, err := known(ctx)
	if err != nil || knownSnapshot == nil || credentials.mcpLaunch == nil {
		return nil, "", mcpchannel.ErrSetup
	}
	upstreams := credentials.mcpLaunch.Upstreams()
	channels, err := mcpchannel.Open(ctx, len(upstreams), ttl, func(ordinal int) mcpchannel.Handler {
		return remoteChannelHandler{bridge: credentials.mcpBridge, ordinal: ordinal}
	})
	if channels != nil {
		credentials.channels = channels
	}
	if err != nil || channels == nil {
		return nil, "", mcpchannel.ErrSetup
	}
	mandatory := channels.OutputGuard()
	if credentials.mcpBridge.ConfigureOutput(knownSnapshot, mandatory) != nil {
		return nil, "", mcpchannel.ErrSetup
	}
	wrapped := func(guardCtx context.Context) (*outputguard.Snapshot, error) {
		snapshot, guardErr := known(guardCtx)
		if guardErr != nil || snapshot == nil {
			return nil, outputguard.ErrGuard
		}
		combined, unionErr := channels.GuardWith(snapshot)
		if unionErr != nil {
			return nil, outputguard.ErrGuard
		}
		return combined, nil
	}
	encoded, err := mcpchannel.EncodeDescriptors(channels.Descriptors())
	if err != nil {
		return nil, "", mcpchannel.ErrSetup
	}
	return wrapped, encoded, nil
}

type remoteOrdinal struct {
	Ordinal int `json:"ordinal"`
}

type remoteChannelHandler struct {
	bridge  *mcpbridge.Runtime
	ordinal int
}

func (h remoteChannelHandler) Close(ctx context.Context) error {
	return h.bridge.CloseBinding(ctx, h.ordinal)
}

func (h remoteChannelHandler) Describe(ctx context.Context) ([]byte, error) {
	request, err := wire.Encode(remoteOrdinal{Ordinal: h.ordinal})
	if err != nil {
		return nil, mcpchannel.ErrSetup
	}
	reply, handled := h.bridge.Handle(ctx, wire.Request{Operation: mcpbridge.OpDescribe, Data: request})
	if !handled || !reply.OK {
		return nil, mcpchannel.ErrSetup
	}
	var envelope mcpbridge.InventoryEnvelope
	if wire.Decode(reply.Data, &envelope) != nil || envelope.Inventory == "" || len(envelope.Inventory) > mcpchannel.MaxInventoryBytes {
		return nil, mcpchannel.ErrSetup
	}
	if _, err := mcpjson.Decode([]byte(envelope.Inventory), mcpchannel.MaxInventoryBytes, 32, mcpbridge.MaxMaskNodes); err != nil {
		return nil, mcpchannel.ErrSetup
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(envelope.Inventory)))
	decoder.UseNumber()
	var inventory mcpbridge.InventoryOutput
	if decoder.Decode(&inventory) != nil || inventory.Ordinal != h.ordinal {
		return nil, mcpchannel.ErrSetup
	}
	return []byte(envelope.Inventory), nil
}

func (h remoteChannelHandler) Call(ctx context.Context, tool string, raw []byte) ([]byte, error) {
	request, err := wire.Encode(mcpbridge.CallInput{Ordinal: h.ordinal, Tool: tool, Arguments: string(raw)})
	if err != nil {
		return nil, mcpchannel.ErrSetup
	}
	reply, handled := h.bridge.Handle(ctx, wire.Request{Operation: mcpbridge.OpCall, Data: request})
	if !handled || !reply.OK {
		return nil, mcpchannel.ErrSetup
	}
	var output mcpbridge.CallOutput
	if wire.Decode(reply.Data, &output) != nil || len(output.Result) > mcpchannel.MaxResultBytes || !json.Valid([]byte(output.Result)) {
		return nil, mcpchannel.ErrSetup
	}
	return []byte(output.Result), nil
}
