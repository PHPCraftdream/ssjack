package mcpdirectory

// CurrentBinding is metadata, not authority to connect or obtain credentials.
func (d *Directory) CurrentBinding(accountID string) (Binding, error) {
	if d == nil {
		return Binding{}, ErrMissing
	}
	account, ok := d.Accounts[accountID]
	if !ok {
		return Binding{}, ErrMissing
	}
	server, ok := d.Servers[account.ServerID]
	if !ok || !server.Enabled || !account.Enabled {
		return Binding{}, ErrMissing
	}
	return Binding{account.ServerID, accountID, server.Revision, account.Revision}, nil
}

// Remember records an explicitly confirmed list, including an empty selection.
func (d *Directory) Remember(profile string, selected []Binding) error {
	if d == nil || d.Validate() != nil || !namePattern.MatchString(profile) || len(selected) > MaxSelections {
		return ErrInvalid
	}
	if _, exists := d.Last[profile]; !exists && len(d.Last) >= 64 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for _, binding := range selected {
		current, err := d.CurrentBinding(binding.AccountID)
		if err != nil || current != binding {
			return ErrChanged
		}
		if seen[binding.AccountID] {
			return ErrInvalid
		}
		seen[binding.AccountID] = true
	}
	d.Last[profile] = append([]Binding{}, selected...)
	return nil
}

// Suggested drops unavailable or changed records; confirmation is still required.
func (d *Directory) Suggested(profile string) []Binding {
	selected := make([]Binding, 0)
	if d == nil {
		return selected
	}
	for _, previous := range d.Last[profile] {
		current, err := d.CurrentBinding(previous.AccountID)
		if err == nil && current == previous {
			selected = append(selected, previous)
		}
	}
	return selected
}
