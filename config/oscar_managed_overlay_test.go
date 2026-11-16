package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"
)

func overlayCoordinator(t *testing.T, path string) (*Coordinator, *int) {
	t.Helper()
	c := NewCoordinator(filepath.Join(filepath.Dir(path), "base.yml"), prometheus.NewRegistry(), promslog.NewNopLogger())
	require.NoError(t, c.EnableManagedInhibition(path, "test-instance"))
	calls := new(int)
	c.Subscribe(func(*Config) error { *calls++; return nil })
	return c, calls
}

func overlayBase(t *testing.T) *Config {
	t.Helper()
	c, err := Load("route:\n  receiver: good\nreceivers:\n- name: good\n")
	require.NoError(t, err)
	return c
}

func overlaySet(name string) ManagedInhibitionSet {
	return ManagedInhibitionSet{Rules: []ManagedInhibitionRule{{Name: name, SourceMatchers: []ManagedInhibitionMatcher{{Label: "severity", Operator: "=", Value: "critical"}}, TargetMatchers: []ManagedInhibitionMatcher{{Label: "severity", Operator: "=", Value: "warning"}}, Equal: []string{"site"}}}}
}

func TestManagedOverlayLifecycle(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "managed.json")
	c, calls := overlayCoordinator(t, path)
	base := overlayBase(t)
	require.NoError(t, c.ApplyConfig(base))
	initial := c.ManagedInhibitionStatus()
	a, err := c.ApplyManagedInhibition(initial.ETag, overlaySet("oscar-inh-1-r1"))
	require.NoError(t, err)
	require.Equal(t, 2, *calls)
	require.Equal(t, a.ActiveDigest, a.PersistedDigest)
	require.True(t, a.ManagedFileHealthy)
	require.Len(t, c.config.InhibitRules, 1)
	require.Empty(t, base.InhibitRules)
	_, err = c.ApplyManagedInhibition(a.ETag, overlaySet("oscar-inh-1-r1"))
	require.NoError(t, err)
	require.Equal(t, 2, *calls, "semantic no-op must not activate")
	b, err := c.ApplyManagedInhibition(a.ETag, ManagedInhibitionSet{})
	require.NoError(t, err)
	again, err := c.ApplyManagedInhibition(b.ETag, overlaySet("oscar-inh-1-r1"))
	require.NoError(t, err)
	require.Equal(t, a.ActiveDigest, again.ActiveDigest)
	require.NotEqual(t, a.ETag, again.ETag)
	_, err = c.ApplyManagedInhibition(a.ETag, ManagedInhibitionSet{})
	require.Error(t, err)
	restarted, _ := overlayCoordinator(t, path)
	require.NoError(t, restarted.ApplyConfig(base))
	require.Equal(t, again.ActiveDigest, restarted.ManagedInhibitionStatus().ActiveDigest)
	require.NotEqual(t, again.ETag, restarted.ManagedInhibitionStatus().ETag)
}

func TestManagedOverlayPersistenceRepair(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"prepare", "rename", "directory_sync"} {
		t.Run(phase, func(t *testing.T) {
			c, calls := overlayCoordinator(t, filepath.Join(t.TempDir(), "managed.json"))
			require.NoError(t, c.ApplyConfig(overlayBase(t)))
			c.managed.diskFault = func(step string) error {
				if step == phase {
					return errors.New("disk failure")
				}
				return nil
			}
			before := c.ManagedInhibitionStatus()
			failed, err := c.ApplyManagedInhibition(before.ETag, overlaySet("oscar-inh-1-r1"))
			require.Error(t, err)
			if phase == "prepare" {
				require.Equal(t, before.ActiveDigest, failed.ActiveDigest)
				require.Equal(t, 1, *calls)
			} else {
				require.NotEqual(t, before.ActiveDigest, failed.ActiveDigest)
				require.False(t, failed.ManagedFileHealthy)
				require.Equal(t, 2, *calls)
			}
			c.managed.diskFault = nil
			repaired, err := c.ApplyManagedInhibition(failed.ETag, overlaySet("oscar-inh-1-r1"))
			require.NoError(t, err)
			require.True(t, repaired.ManagedFileHealthy)
			require.Equal(t, repaired.ActiveDigest, repaired.PersistedDigest)
			require.Equal(t, 2, *calls)
		})
	}
}

func TestManagedOverlayStartupFallback(t *testing.T) {
	t.Parallel()
	for _, contents := range []string{"{", `{"schema_version":99,"generation":1,"rules":[]}`, `{"schema_version":1,"generation":1,"rules":[{"name":"invalid"}]}`} {
		t.Run(contents, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed.json")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
			c, _ := overlayCoordinator(t, path)
			require.NoError(t, c.ApplyConfig(overlayBase(t)))
			status := c.ManagedInhibitionStatus()
			require.False(t, status.ManagedFileHealthy)
			require.Empty(t, status.Rules)
			actual, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, contents, string(actual))
		})
	}
}

func TestManagedOverlayActivationFailureAndSubscriberCount(t *testing.T) {
	t.Parallel()
	c, _ := overlayCoordinator(t, filepath.Join(t.TempDir(), "managed.json"))
	require.NoError(t, c.ApplyConfig(overlayBase(t)))
	before := c.ManagedInhibitionStatus()
	c.subscribers = []func(*Config) error{func(*Config) error { return errors.New("broken template secret") }}
	failed, err := c.ApplyManagedInhibition(before.ETag, overlaySet("oscar-inh-1-r1"))
	require.Error(t, err)
	require.Equal(t, before.ActiveDigest, failed.ActiveDigest)
	require.NotContains(t, err.Error(), "secret")
	c.Subscribe(func(*Config) error { return nil })
	_, err = c.ApplyManagedInhibition(before.ETag, overlaySet("oscar-inh-1-r1"))
	require.Error(t, err, "managed activation requires exactly one transactional subscriber")
}

func TestManagedOverlayRepairFailureReportsUnhealthy(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "managed.json")
	c, _ := overlayCoordinator(t, path)
	require.NoError(t, c.ApplyConfig(overlayBase(t)))
	active, err := c.ApplyManagedInhibition(c.ManagedInhibitionStatus().ETag, overlaySet("oscar-inh-1-r1"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	c.managed.diskFault = func(string) error { return errors.New("disk full") }
	failed, err := c.ApplyManagedInhibition(active.ETag, overlaySet("oscar-inh-1-r1"))
	require.Error(t, err)
	require.False(t, failed.ManagedFileHealthy)
	require.Empty(t, failed.PersistedDigest)
}

func TestManagedOverlayBaseReloadAndConflicts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "managed.json")
	c, calls := overlayCoordinator(t, path)
	base := overlayBase(t)
	require.NoError(t, c.ApplyConfig(base))
	active, err := c.ApplyManagedInhibition(c.ManagedInhibitionStatus().ETag, overlaySet("oscar-inh-1-r1"))
	require.NoError(t, err)
	// An API apply uses the last successful base object, even with a broken file.
	require.NoError(t, os.WriteFile(c.configFilePath, []byte("invalid: ["), 0o600))
	active, err = c.ApplyManagedInhibition(active.ETag, overlaySet("oscar-inh-1-r2"))
	require.NoError(t, err)
	require.Error(t, c.Reload())
	require.Equal(t, active.ActiveDigest, c.ManagedInhibitionStatus().ActiveDigest)
	// Reserved-name base reload is rejected before touching the running subscriber.
	conflicting := *base
	conflicting.InhibitRules = c.managed.active.Rules
	before := *calls
	require.Error(t, c.ApplyConfig(&conflicting))
	require.Equal(t, before, *calls)
	restarted, _ := overlayCoordinator(t, path)
	require.NoError(t, restarted.ApplyConfig(&conflicting))
	fallback := restarted.ManagedInhibitionStatus()
	require.False(t, fallback.ManagedFileHealthy)
	require.Empty(t, fallback.Rules)
	require.Equal(t, []string{"oscar-inh-1-r2"}, fallback.ExternalRuleNames)
	_, err = restarted.ApplyManagedInhibition(fallback.ETag, ManagedInhibitionSet{})
	require.Error(t, err)
	// Fixing base names permits recovery from authoritative desired state.
	require.NoError(t, restarted.ApplyConfig(base))
	recovered, err := restarted.ApplyManagedInhibition(fallback.ETag, overlaySet("oscar-inh-1-r2"))
	require.NoError(t, err)
	require.True(t, recovered.ManagedFileHealthy)
}

func TestManagedOverlayAdditionalStartupFailures(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"unreadable", "oversized", "lowered_limit"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed.json")
			switch kind {
			case "unreadable":
				require.NoError(t, os.Mkdir(path, 0o700))
			case "oversized":
				require.NoError(t, os.WriteFile(path, make([]byte, ManagedInhibitionMaxBodyBytes+4097), 0o600))
			case "lowered_limit":
				rules := make([]ManagedInhibitionRule, ManagedInhibitionMaxRules+1)
				data, err := json.Marshal(managedOverlayFile{SchemaVersion: 1, Rules: rules})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, data, 0o600))
			}
			c, _ := overlayCoordinator(t, path)
			require.NoError(t, c.ApplyConfig(overlayBase(t)))
			require.False(t, c.ManagedInhibitionStatus().ManagedFileHealthy)
		})
	}
}

func TestManagedOverlayCrashRecovery(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"prepare", "write", "file_sync", "close", "rename", "directory_sync"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed.json")
			c, _ := overlayCoordinator(t, path)
			require.NoError(t, c.ApplyConfig(overlayBase(t)))
			old, err := c.ApplyManagedInhibition(c.ManagedInhibitionStatus().ETag, overlaySet("oscar-inh-1-r1"))
			require.NoError(t, err)
			c.managed.diskFault = func(step string) error {
				if step == phase {
					return errors.New("crash point")
				}
				return nil
			}
			failed, err := c.ApplyManagedInhibition(old.ETag, overlaySet("oscar-inh-1-r2"))
			require.Error(t, err)
			restarted, _ := overlayCoordinator(t, path)
			require.NoError(t, restarted.ApplyConfig(overlayBase(t)))
			want := old.ActiveDigest
			if phase == "directory_sync" {
				want = failed.ActiveDigest
			}
			require.Equal(t, want, restarted.ManagedInhibitionStatus().ActiveDigest)
			files, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".oscar-inhibition-*"))
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
}

func TestManagedOverlayConcurrentWritersAndLostResponse(t *testing.T) {
	t.Parallel()
	c, _ := overlayCoordinator(t, filepath.Join(t.TempDir(), "managed.json"))
	require.NoError(t, c.ApplyConfig(overlayBase(t)))
	etag := c.ManagedInhibitionStatus().ETag
	results := make(chan error, 2)
	for _, name := range []string{"oscar-inh-1-r1", "oscar-inh-1-r2"} {
		go func() { _, err := c.ApplyManagedInhibition(etag, overlaySet(name)); results <- err }()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else {
			var conflict *ManagedInhibitionError
			require.ErrorAs(t, err, &conflict)
			require.Equal(t, "precondition_failed", conflict.Code)
		}
	}
	require.Equal(t, 1, successes)
	// If the publisher lost its response, the earlier ETag remains stale.
	observed := c.ManagedInhibitionStatus()
	_, err := c.ApplyManagedInhibition(etag, ManagedInhibitionSet{Rules: observed.Rules})
	require.Error(t, err)
	acknowledged, err := c.ApplyManagedInhibition(observed.ETag, ManagedInhibitionSet{Rules: observed.Rules})
	require.NoError(t, err)
	require.Equal(t, observed.ETag, acknowledged.ETag)
}

func TestManagedOverlayStartupRejectsIncompleteDocument(t *testing.T) {
	t.Parallel()
	for _, contents := range []string{`{"schema_version":1}`, `{"schema_version":1,"rules":null}`, `{"schema_version":1,"rules":[],"unexpected":true}`} {
		t.Run(contents, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed.json")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
			c, _ := overlayCoordinator(t, path)
			require.NoError(t, c.ApplyConfig(overlayBase(t)))
			require.False(t, c.ManagedInhibitionStatus().ManagedFileHealthy)
		})
	}
}

func TestManagedOverlayMatcherValuePresence(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"source_matchers", "target_matchers"} {
		for _, value := range []string{"missing", "null", "empty"} {
			t.Run(side+"/"+value, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "managed.json")
				source := map[string]any{"label": "alertname", "operator": "=", "value": "Parent"}
				target := map[string]any{"label": "alertname", "operator": "!=", "value": "Child"}
				matcher := source
				if side == "target_matchers" {
					matcher = target
				}
				switch value {
				case "missing":
					delete(matcher, "value")
				case "null":
					matcher["value"] = nil
				case "empty":
					matcher["value"] = ""
				}
				contents, err := json.Marshal(map[string]any{"schema_version": 1, "generation": 1, "rules": []any{map[string]any{"name": "oscar-inh-1-r1", "source_matchers": []any{source}, "target_matchers": []any{target}, "equal": []string{"site"}}}})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, contents, 0o600))
				_, _, readErr := readManagedOverlay(path)
				c, calls := overlayCoordinator(t, path)
				require.NoError(t, c.ApplyConfig(overlayBase(t)))
				require.Equal(t, 1, *calls)
				status := c.ManagedInhibitionStatus()
				if value == "empty" {
					require.NoError(t, readErr)
					require.True(t, status.ManagedFileHealthy)
					require.Len(t, status.Rules, 1)
					require.Len(t, c.config.InhibitRules, 1)
					matchers := status.Rules[0].SourceMatchers
					if side == "target_matchers" {
						matchers = status.Rules[0].TargetMatchers
					}
					require.Contains(t, matchers, ManagedInhibitionMatcher{Label: "alertname", Operator: matcher["operator"].(string), Value: ""})
				} else {
					require.Error(t, readErr)
					var validation *ManagedInhibitionValidationError
					require.ErrorAs(t, readErr, &validation)
					require.Equal(t, "rules.0."+side+".0.value", validation.Field)
					require.False(t, status.ManagedFileHealthy)
					require.Empty(t, status.Rules)
					require.Empty(t, status.PersistedDigest)
					require.Empty(t, c.config.InhibitRules)
					require.Equal(t, "good", c.config.Route.Receiver)
				}
				actual, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, contents, actual)
			})
		}
	}
}
