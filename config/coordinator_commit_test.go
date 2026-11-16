package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorApplyRetainsLastGoodConfiguration(t *testing.T) {
	t.Parallel()
	c := NewCoordinator("unused", prometheus.NewRegistry(), promslog.NewNopLogger())
	good, err := Load("route:\n  receiver: good\nreceivers:\n- name: good\n")
	require.NoError(t, err)
	bad, err := Load("route:\n  receiver: bad\nreceivers:\n- name: bad\n")
	require.NoError(t, err)
	wantErr := errors.New("activation failed")
	c.Subscribe(func(candidate *Config) error {
		if candidate == bad {
			return wantErr
		}
		return nil
	})
	require.NoError(t, c.ApplyConfig(good))
	require.ErrorIs(t, c.ApplyConfig(bad), wantErr)
	require.Same(t, good, c.config, "rejected candidate must not become the applied base")
	require.Error(t, c.ApplyConfig(nil))
	require.Same(t, good, c.config)
}

func TestCoordinatorReloadRetainsLastGoodConfiguration(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "alertmanager.yml")
	require.NoError(t, os.WriteFile(path, []byte("route:\n  receiver: good\nreceivers:\n- name: good\n"), 0o600))
	c := NewCoordinator(path, prometheus.NewRegistry(), promslog.NewNopLogger())
	c.Subscribe(func(candidate *Config) error {
		if candidate.Route.Receiver == "bad" {
			return errors.New("activation failed")
		}
		return nil
	})
	require.NoError(t, c.Reload())
	good := c.config
	require.NoError(t, os.WriteFile(path, []byte("route:\n  receiver: bad\nreceivers:\n- name: bad\n"), 0o600))
	require.Error(t, c.Reload())
	require.Same(t, good, c.config)
	require.NoError(t, os.WriteFile(path, []byte("invalid: ["), 0o600))
	require.Error(t, c.Reload())
	require.Same(t, good, c.config)
}
