package routes

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Flags collects repeatable owner-supplied per-application routes.
type Flags []string

func (f Flags) String() string { return strings.Join(f, " ") }

func (f *Flags) Set(value string) error {
	name, spec, ok := strings.Cut(value, "=")
	if !ok || name == "" || vault.ValidateApprovalName(name) != nil || spec == "" {
		return errors.New("--app-route-for must be APP=incus:CONTAINER:USER")
	}
	if _, _, err := application.ParseRoute(spec); err != nil {
		return errors.New("--app-route-for must be APP=incus:CONTAINER:USER")
	}
	for _, existing := range *f {
		if previous, _, _ := strings.Cut(existing, "="); previous == name {
			return fmt.Errorf("duplicate --app-route-for for application '%s'", name)
		}
	}
	*f = append(*f, value)
	return nil
}

// Overrides returns the validated application-to-route specifications.
func (f Flags) Overrides() map[string]string {
	out := make(map[string]string, len(f))
	for _, value := range f {
		name, spec, _ := strings.Cut(value, "=")
		out[name] = spec
	}
	return out
}

// CheckEnabled rejects route flags that do not name an enabled application.
func (f Flags) CheckEnabled(enabled map[string]bool) error {
	for _, value := range f {
		name, _, _ := strings.Cut(value, "=")
		if !enabled[name] {
			return fmt.Errorf("unknown application '%s' for --app-route-for", name)
		}
	}
	return nil
}

// Spec is the resolved container and guest user for an application.
type Spec struct{ Container, User string }

// Resolve applies flag, stored approval, then global route precedence.
func Resolve(overrides, vaultRoutes map[string]string, globalContainer, globalUser string, names []string) map[string]Spec {
	resolved := make(map[string]Spec, len(names))
	for _, name := range names {
		container, user := globalContainer, globalUser
		if spec, ok := overrides[name]; ok {
			container, user, _ = application.ParseRoute(spec)
		} else if spec, ok := vaultRoutes[name]; ok {
			container, user, _ = application.ParseRoute(spec)
		}
		resolved[name] = Spec{Container: container, User: user}
	}
	return resolved
}

// VaultRoutes returns stored routes only for approved discovered applications.
func VaultRoutes(approvals []vault.Approval, discoveredNames map[string]bool) map[string]string {
	result := make(map[string]string)
	for _, approval := range approvals {
		if approval.Route != "" && discoveredNames[approval.Name] {
			result[approval.Name] = approval.Route
		}
	}
	return result
}

var _ flag.Value = (*Flags)(nil)
