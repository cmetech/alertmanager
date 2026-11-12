package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/config"
)

func TestManagedInhibitionUsesOriginalTemplateLifecycle(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "notification.tmpl")
	require.NoError(t, os.WriteFile(tmpl, []byte(`{{ define "custom" }}original{{ end }}`), 0o600))
	base := mustConfig(t)
	base.Templates = []string{tmpl}
	c := config.NewCoordinator(filepath.Join(dir, "not-read.yml"), prometheus.NewRegistry(), promslog.NewNopLogger())
	require.NoError(t, c.EnableManagedInhibition(filepath.Join(dir, "managed.json"), "test"))
	c.Subscribe(r.reload)
	require.NoError(t, c.ApplyConfig(base))
	originalDispatcher := r.dispatcher.Load()
	desired := config.ManagedInhibitionSet{Rules: []config.ManagedInhibitionRule{{Name: "oscar-inh-1-r1", SourceMatchers: []config.ManagedInhibitionMatcher{{Label: "severity", Operator: "=", Value: "critical"}}, TargetMatchers: []config.ManagedInhibitionMatcher{{Label: "severity", Operator: "=", Value: "warning"}}, Equal: []string{"site"}}}}
	// Managed apply reparses the referenced file, without rereading the base YAML.
	require.NoError(t, os.WriteFile(tmpl, []byte("{{ broken"), 0o600))
	initial := c.ManagedInhibitionStatus()
	failed, err := c.ApplyManagedInhibition(initial.ETag, desired)
	require.Error(t, err)
	require.Equal(t, initial.ActiveDigest, failed.ActiveDigest)
	require.Same(t, originalDispatcher, r.dispatcher.Load())
	require.NoError(t, os.WriteFile(tmpl, []byte(`{{ define "custom" }}updated{{ end }}`), 0o600))
	active, err := c.ApplyManagedInhibition(failed.ETag, desired)
	require.NoError(t, err)
	require.NotSame(t, originalDispatcher, r.dispatcher.Load())
	activeDispatcher := r.dispatcher.Load()
	// Same-content confirmation and disk repair must never reparse/rebuild runtime resources.
	require.NoError(t, os.WriteFile(tmpl, []byte("{{ broken again"), 0o600))
	_, err = c.ApplyManagedInhibition(active.ETag, desired)
	require.NoError(t, err)
	require.Same(t, activeDispatcher, r.dispatcher.Load())
	require.NoError(t, os.Remove(filepath.Join(dir, "managed.json")))
	repaired, err := c.ApplyManagedInhibition(active.ETag, desired)
	require.NoError(t, err)
	require.True(t, repaired.ManagedFileHealthy)
	require.Same(t, activeDispatcher, r.dispatcher.Load())
}
