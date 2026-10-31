package main

import (
	"context"
	"errors"
	"fmt"
)

func runAppstore(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 1, errors.New("usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock HARNESS [ARGS...]")
	}
	switch args[0] {
	case "setup":
		if len(args) != 2 {
			return 1, errors.New("usage: ssjack appstore setup DIR")
		}
		return runAppstoreSetup(ctx, args[1])
	case "put":
		if len(args) != 2 {
			return 1, errors.New("usage: ssjack appstore put DIR")
		}
		return runAppstorePut(ctx, args[1])
	case "inspect":
		if len(args) != 2 {
			return 1, errors.New("usage: ssjack appstore inspect DIR")
		}
		return runAppstoreInspect(ctx, args[1])
	case "unlock":
		if len(args) < 2 {
			return 1, errors.New("usage: ssjack appstore unlock HARNESS [ARGS...]")
		}
		return runAppstoreUnlock(ctx, args[1:])
	default:
		return 1, fmt.Errorf("usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock HARNESS [ARGS...]")
	}
}
