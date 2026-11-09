package mcpdirectory

func (d *Directory) Record() map[string]any {
	servers, accounts, last := make(map[string]any), make(map[string]any), make(map[string]any)
	for id, s := range d.Servers {
		servers[id] = map[string]any{"name": s.Name, "url": s.URL, "enabled": s.Enabled, "revision": s.Revision}
	}
	for id, a := range d.Accounts {
		headers := make([]any, 0, len(a.Headers))
		for _, h := range a.Headers {
			headers = append(headers, map[string]any{"name": h.Name, "value": h.Value})
		}
		accounts[id] = map[string]any{"server_id": a.ServerID, "name": a.Name, "enabled": a.Enabled, "revision": a.Revision, "auth": map[string]any{"kind": a.Auth.Kind, "username": a.Auth.Username, "secret": a.Auth.Secret}, "headers": headers}
	}
	for context, selected := range d.Last {
		bindings := make([]any, 0, len(selected))
		for _, b := range selected {
			bindings = append(bindings, map[string]any{"server_id": b.ServerID, "account_id": b.AccountID, "server_revision": b.ServerRevision, "account_revision": b.AccountRevision})
		}
		last[context] = bindings
	}
	return map[string]any{"servers": servers, "accounts": accounts, "last": last}
}
func object(raw any, keys ...string) (map[string]any, bool) {
	value, ok := raw.(map[string]any)
	if !ok || len(value) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return nil, false
		}
	}
	return value, true
}

// ValidateFields rejects unknown nested data before typed decoding can discard it.
func ValidateFields(raw any) error {
	d, ok := object(raw, "servers", "accounts", "last")
	if !ok {
		return ErrInvalid
	}
	servers, ok := d["servers"].(map[string]any)
	if !ok || len(servers) > MaxServers {
		return ErrInvalid
	}
	accounts, ok := d["accounts"].(map[string]any)
	if !ok || len(accounts) > MaxAccounts {
		return ErrInvalid
	}
	last, ok := d["last"].(map[string]any)
	if !ok || len(last) > 64 {
		return ErrInvalid
	}
	for _, raw := range servers {
		if _, ok := object(raw, "name", "url", "enabled", "revision"); !ok {
			return ErrInvalid
		}
	}
	for _, raw := range accounts {
		a, ok := object(raw, "server_id", "name", "enabled", "revision", "auth", "headers")
		if !ok {
			return ErrInvalid
		}
		if _, ok := object(a["auth"], "kind", "username", "secret"); !ok {
			return ErrInvalid
		}
		headers, ok := a["headers"].([]any)
		if !ok || len(headers) > 4 {
			return ErrInvalid
		}
		for _, h := range headers {
			if _, ok := object(h, "name", "value"); !ok {
				return ErrInvalid
			}
		}
	}
	for _, raw := range last {
		selected, ok := raw.([]any)
		if !ok || len(selected) > MaxSelections {
			return ErrInvalid
		}
		for _, b := range selected {
			if _, ok := object(b, "server_id", "account_id", "server_revision", "account_revision"); !ok {
				return ErrInvalid
			}
		}
	}
	return nil
}
