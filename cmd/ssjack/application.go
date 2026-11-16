package main

import (
	"errors"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

// appDirectoryFlags collects repeatable --app DIR registrations.
type appDirectoryFlags []string

func (l *appDirectoryFlags) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, " ")
}

func (l *appDirectoryFlags) Set(value string) error {
	if value == "" {
		return errors.New("--app requires a directory")
	}
	*l = append(*l, value)
	return nil
}

// registeredApplications validates every --app directory and the optional
// --app-route before the vault is unlocked. It returns nil when none is given.
func registeredApplications(directories []string, route, profile string, runner remote.StreamRunner) (*application.Options, error) {
	if len(directories) == 0 {
		if route != "" {
			return nil, errors.New("--app-route requires --app")
		}
		return nil, nil
	}
	if len(directories) > application.MaxApplications {
		return nil, errors.New("too many --app directories")
	}
	container, user, err := application.ParseRoute(route)
	if err != nil {
		return nil, err
	}
	apps := make([]application.App, 0, len(directories))
	names := make(map[string]bool, len(directories))
	for _, directory := range directories {
		app, err := application.LoadDescriptor(directory)
		if err != nil {
			return nil, err
		}
		if names[app.Name] {
			return nil, errors.New("--app directories declare the same application name twice")
		}
		names[app.Name] = true
		apps = append(apps, app)
	}
	return &application.Options{
		Apps:      apps,
		Profile:   profile,
		Runner:    runner,
		Container: container,
		User:      user,
	}, nil
}
