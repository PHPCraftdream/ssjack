package ownercommands

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestEveryMenuManagementActionHasACommandAndEveryCommandHasAForm(t *testing.T) {
	b := fixture(t)
	type route struct {
		server, account string
		path            []string
	}
	pages := []route{{}, {path: []string{"Servers"}}, {server: "production"}, {server: "production", account: "main"}, {path: []string{"Global secrets"}}, {path: []string{"Global secrets", "token"}}, {server: "production", path: []string{"Server secrets"}}}
	found := make(map[string]bool)
	actionLine := regexp.MustCompile(`(?m)^"[a-z]+(?:-[a-z]+)*"$`)
	for _, page := range pages {
		seen := make(map[string]bool)
		for i := 0; i < 40; i++ {
			m := menu(t, b, page.server, page.account, page.path...)
			for j := 0; j < i; j++ {
				key(m, tea.KeyDown)
			}
			label := selected(m)
			if seen[label] {
				break
			}
			seen[label] = true
			key(m, tea.KeyEnter)
			view := m.View().Content
			if strings.Contains(view, "Unsupported owner action") {
				t.Fatal("menu action has no handler")
			}
			if action := strings.Trim(actionLine.FindString(view), `"`); action != "" {
				if _, ok := ownercommand.Lookup(action); !ok {
					t.Fatalf("menu-only management action: %s", action)
				}
				found[action] = true
			}
		}
	}
	for _, spec := range ownercommand.Specs() {
		if !found[spec.Action] {
			t.Errorf("CLI-only management action: %s", spec.Action)
		}
		args := []string{spec.Action}
		switch spec.Scope {
		case "server":
			args = append(args, "--server", "production")
		case "account":
			args = append(args, "--server", "production", "--account", "main")
		case "secrets":
			args = append(args, "--scope", "global")
		case "secret":
			args = append(args, "--scope", "global", "--secret", "token")
		}
		request, err := ownercommand.Parse(args, "", "")
		if err != nil {
			t.Fatal(err)
		}
		m := ownertui.New(context.Background(), b)
		if err := m.ConfigureCommand(request); err != nil {
			t.Fatalf("%s: %v", spec.Action, err)
		}
		if strings.Trim(actionLine.FindString(m.View().Content), `"`) != spec.Action {
			t.Fatalf("command bypassed the shared form: %s", spec.Action)
		}
	}
}

func accounts(v *vault.Vault) map[string]map[string]vault.Target {
	result := make(map[string]map[string]vault.Target)
	for _, server := range v.Servers {
		result[server.Name] = make(map[string]vault.Target)
		for account, profile := range server.Accounts {
			result[server.Name][account] = v.Targets[profile]
		}
	}
	return result
}

func TestParameterizedCommandsAndMenuProduceIdenticalOwnerEffects(t *testing.T) {
	cases := []struct {
		args, path      []string
		server, account string
		values          map[string]string
	}{
		{[]string{"rename-server", "--server", "production", "--name", "renamed"}, []string{"[Rename server]"}, "production", "", nil},
		{[]string{"edit-server", "--server", "production", "--address", "changed.invalid:2222"}, []string{"[Edit server connection]"}, "production", "", nil},
		{[]string{"edit-account", "--server", "production", "--account", "main", "--login", "changed", "--auth", "password", "--usage", "human"}, []string{"[Edit SSH account]"}, "production", "main", map[string]string{"Credential": "synthetic-input-secret"}},
		{[]string{"add-account", "--server", "production", "--account", "second", "--login", "second", "--auth", "password"}, []string{"[Add SSH account]"}, "production", "", map[string]string{"Credential": "synthetic-input-secret"}},
		{[]string{"edit-proxy", "--server", "production", "--type", "socks5", "--address", "proxy.invalid:1080", "--login", "proxy-user"}, []string{"[Edit SSH proxy]"}, "production", "", map[string]string{"Proxy password": "synthetic-input-secret"}},
		{[]string{"add-secret", "--scope", "global", "--name", "new-token"}, []string{"Global secrets", "[Add secret]"}, "", "", map[string]string{"Value": "synthetic-input-secret"}},
		{[]string{"edit-secret", "--scope", "global", "--secret", "token"}, []string{"Global secrets", "token", "[Change secret value]"}, "", "", map[string]string{"Value": "synthetic-input-secret"}},
		{[]string{"remove-secret", "--scope", "global", "--secret", "token"}, []string{"Global secrets", "token", "[Remove secret]"}, "", "", map[string]string{"Confirmation": "REMOVE"}},
		{[]string{"export", "--scope", "account", "--server", "production", "--account", "main", "--destination", "synthetic.zip", "--format", "plaintext"}, []string{"Export account and server secrets"}, "production", "main", map[string]string{"Confirmation": "EXPORT PLAINTEXT"}},
		{[]string{"link", "--directory", "synthetic-store"}, []string{"Link secret store"}, "", "", map[string]string{"Store unlock secret": "synthetic-input-secret"}},
		{[]string{"pending", "--action", "retry-db"}, []string{"Pending change"}, "", "", nil},
	}
	pin := fixture(t).state.Targets["production"].HostKeys[0]
	cases = append(cases, struct {
		args, path      []string
		server, account string
		values          map[string]string
	}{
		[]string{"add-server", "--name", "additional", "--address", "other.invalid:22", "--account", "main", "--login", "operator", "--auth", "password", "--usage", "both", "--host-keys", pin},
		[]string{"Servers", "[Add server]"}, "", "", map[string]string{"Credential": "synthetic-input-secret"},
	})
	for _, test := range cases {
		t.Run(test.args[0], func(t *testing.T) {
			left, right := fixture(t), fixture(t)
			request, err := ownercommand.Parse(test.args, "", "")
			if err != nil {
				t.Fatal(err)
			}
			values := make(map[string]string)
			for label, value := range request.Fields {
				values[label] = value
			}
			for label, value := range test.values {
				values[label] = value
			}
			command := ownertui.New(context.Background(), left)
			if err := command.ConfigureCommand(request); err != nil {
				t.Fatal(err)
			}
			interactive := menu(t, right, test.server, test.account, test.path...)
			apply(t, command, values)
			apply(t, interactive, values)
			if err := command.CommandResult(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(accounts(left.state), accounts(right.state)) || !reflect.DeepEqual(left.changes, right.changes) || !reflect.DeepEqual(left.exports, right.exports) || !reflect.DeepEqual(left.calls, right.calls) || left.linkedDirectory != right.linkedDirectory || !reflect.DeepEqual(left.linkedMaster, right.linkedMaster) {
				t.Fatal("command and menu used different owner effects or scopes")
			}
		})
	}
}
