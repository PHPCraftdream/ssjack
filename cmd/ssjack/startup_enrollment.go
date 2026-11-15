package main

import (
	"errors"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
)

type enrollmentInputs struct {
	mode                                               string
	metadataPath, policyPath, identityPath             string
	metadataSupplied, policySupplied, identitySupplied bool
}

// loadEnrollment validates the declarative enrollment flags and loads the
// snapshots they name; nothing is returned when none were supplied.
func loadEnrollment(in enrollmentInputs) (*enrollment.Metadata, *enrollment.Policy, *enrollment.Snapshot, error) {
	var metadata *enrollment.Metadata
	var policy *enrollment.Policy
	var identity *enrollment.Snapshot
	if in.metadataSupplied {
		if in.metadataPath == "" {
			return nil, nil, nil, errors.New("--enrollment-metadata requires a non-empty absolute path")
		}
		if in.mode != string(broker.ModeDeclarative) {
			return nil, nil, nil, errors.New("--enrollment-metadata requires --mode declarative")
		}
		if !filepath.IsAbs(in.metadataPath) {
			return nil, nil, nil, errors.New("--enrollment-metadata path must be absolute")
		}
		loaded, err := enrollment.Load(in.metadataPath)
		if err != nil {
			return nil, nil, nil, err
		}
		metadata = &loaded
		if in.policySupplied {
			if in.policyPath == "" || !filepath.IsAbs(in.policyPath) {
				return nil, nil, nil, errors.New("--policy-snapshot requires a non-empty absolute path")
			}
			installed, err := enrollment.LoadPolicy(in.policyPath, loaded)
			if err != nil {
				return nil, nil, nil, err
			}
			policy = &installed
		}
		if in.identitySupplied {
			if in.identityPath == "" || !filepath.IsAbs(in.identityPath) {
				return nil, nil, nil, errors.New("--enrollment-identity requires a non-empty absolute path")
			}
			if policy == nil {
				return nil, nil, nil, errors.New("--enrollment-identity requires --policy-snapshot")
			}
			loaded, err := enrollment.LoadSnapshot(in.identityPath, loaded, *policy)
			if err != nil {
				return nil, nil, nil, err
			}
			identity = &loaded
		}
	} else if in.policySupplied {
		return nil, nil, nil, errors.New("--policy-snapshot requires --enrollment-metadata")
	} else if in.identitySupplied {
		return nil, nil, nil, errors.New("--enrollment-identity requires --enrollment-metadata")
	}
	return metadata, policy, identity, nil
}
