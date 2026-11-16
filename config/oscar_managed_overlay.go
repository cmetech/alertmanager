package config

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/alertmanager/config/common"
)

// ManagedInhibitionError exposes a safe error code; operational details are logged.
type ManagedInhibitionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ManagedInhibitionError) Error() string { return e.Message }
func managedError(code, message string) error {
	return &ManagedInhibitionError{Code: code, Message: message}
}

// ManagedInhibitionStatus separates live state from confirmed durable state.
type ManagedInhibitionStatus struct {
	ContractVersion            int                     `json:"contract_version"`
	InstanceID                 string                  `json:"instance_id"`
	RuntimeEpoch               string                  `json:"runtime_epoch"`
	ETag                       string                  `json:"etag"`
	ActiveDigest               string                  `json:"active_digest"`
	PersistedDigest            string                  `json:"persisted_digest"`
	ActiveGeneration           uint64                  `json:"active_generation"`
	PersistedGeneration        uint64                  `json:"persisted_generation"`
	ManagedFileHealthy         bool                    `json:"managed_file_healthy"`
	LastSuccessfulBaseIdentity string                  `json:"last_successful_base_identity"`
	Rules                      []ManagedInhibitionRule `json:"rules"`
	ExternalRuleNames          []string                `json:"external_rule_names"`
	Error                      *ManagedInhibitionError `json:"error,omitempty"`
}
type managedOverlay struct {
	path   string
	status ManagedInhibitionStatus
	active *CompiledManagedInhibition
	loaded bool
	// diskFault is a unit-test crash-point hook. Production uses real filesystem operations.
	diskFault func(string) error
}
type managedOverlayFile struct {
	SchemaVersion int                    `json:"schema_version"`
	Generation    uint64                 `json:"generation"`
	Rules         ManagedInhibitionRules `json:"rules"`
}

// EnableManagedInhibition configures the overlay before the first base activation.
func (c *Coordinator) EnableManagedInhibition(path, instanceID string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.config != nil || c.managed != nil || path == "" {
		return errors.New("managed inhibition must be configured once before activation")
	}
	epoch := make([]byte, 16)
	if _, err := rand.Read(epoch); err != nil {
		return err
	}
	empty, _ := CompileManagedInhibition(ManagedInhibitionSet{})
	c.managed = &managedOverlay{path: path, active: empty, status: ManagedInhibitionStatus{ContractVersion: 1, InstanceID: instanceID, RuntimeEpoch: hex.EncodeToString(epoch), ActiveDigest: empty.Digest, PersistedDigest: empty.Digest, ManagedFileHealthy: true, Rules: empty.Definition.Rules, ExternalRuleNames: []string{}}}
	c.managed.refreshETag()
	return nil
}

func (m *managedOverlay) refreshETag() {
	m.status.ETag = fmt.Sprintf(`"%s-%d"`, m.status.RuntimeEpoch, m.status.ActiveGeneration)
}

func (m *managedOverlay) fault(phase string) error {
	if m.diskFault != nil {
		return m.diskFault(phase)
	}
	return nil
}

func (c *Coordinator) managedFailure(code, message string, detail error) error {
	err := &ManagedInhibitionError{Code: code, Message: message}
	c.managed.status.Error = err
	c.logger.Error(message, "code", code, "err", detail)
	return err
}

func readManagedOverlay(path string) (*CompiledManagedInhibition, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, ManagedInhibitionMaxBodyBytes+4097))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > ManagedInhibitionMaxBodyBytes+4096 {
		return nil, 0, errors.New("managed file byte limit exceeded")
	}
	var disk managedOverlayFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disk); err != nil {
		return nil, 0, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, 0, errors.New("trailing managed file data")
	}
	if disk.Rules == nil {
		return nil, 0, errors.New("managed file requires an explicit rules array")
	}
	if disk.SchemaVersion != 1 {
		return nil, 0, errors.New("unsupported managed file schema")
	}
	compiled, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: disk.Rules})
	return compiled, disk.Generation, err
}

func (c *Coordinator) loadManagedOverlay() {
	m := c.managed
	m.loaded = true
	compiled, generation, err := readManagedOverlay(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		m.status.ManagedFileHealthy = false
		m.status.PersistedDigest = ""
		_ = c.managedFailure("overlay_unhealthy", "Managed overlay could not be loaded; base configuration remains authoritative.", err)
		return
	}
	m.active = compiled
	m.status.ActiveDigest = compiled.Digest
	m.status.PersistedDigest = compiled.Digest
	m.status.ActiveGeneration = generation
	m.status.PersistedGeneration = generation
	m.status.Rules = compiled.Definition.Rules
	m.refreshETag()
}

func mergeManaged(base *Config, managed *CompiledManagedInhibition) (*Config, error) {
	for _, rule := range base.InhibitRules {
		if strings.HasPrefix(rule.Name, ManagedInhibitionPrefix) {
			return nil, managedError("base_conflict", "Base configuration uses a reserved managed inhibition name.")
		}
	}
	merged := *base
	merged.InhibitRules = append([]common.InhibitRule{}, base.InhibitRules...)
	for _, rule := range managed.Rules {
		rule.ManagedOrigin = true
		merged.InhibitRules = append(merged.InhibitRules, rule)
	}
	return &merged, nil
}

// activateBaseLocked merges under the same lock as API mutations and commits only on success.
func (c *Coordinator) activateBaseLocked(base *Config) error {
	candidate := base
	if c.managed != nil {
		if len(c.subscribers) != 1 {
			return errors.New("managed inhibition requires exactly one transactional configuration subscriber")
		}
		startup := !c.managed.loaded
		if startup {
			c.loadManagedOverlay()
		}
		var err error
		candidate, err = mergeManaged(base, c.managed.active)
		if err != nil {
			if !startup {
				return err
			}
			c.managed.status.ManagedFileHealthy = false
			_ = c.managedFailure("base_conflict", "Managed overlay conflicts with base configuration; base configuration remains authoritative.", err)
			candidate = base
			empty, _ := CompileManagedInhibition(ManagedInhibitionSet{})
			c.managed.active = empty
			c.managed.status.ActiveDigest = empty.Digest
			c.managed.status.Rules = empty.Definition.Rules
		}
	}
	if err := c.notifySubscribers(candidate); err != nil {
		return err
	}
	c.config = candidate
	c.base = base
	if c.managed != nil {
		sum := sha256.Sum256([]byte(base.original))
		c.managed.status.LastSuccessfulBaseIdentity = hex.EncodeToString(sum[:])
		c.managed.status.ExternalRuleNames = []string{}
		for _, rule := range base.InhibitRules {
			c.managed.status.ExternalRuleNames = append(c.managed.status.ExternalRuleNames, rule.Name)
		}
	}
	return nil
}

// ManagedInhibitionStatus returns a detached snapshot, safe for callers to retain.
func (c *Coordinator) ManagedInhibitionStatus() ManagedInhibitionStatus {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.managedStatusLocked()
}

func (c *Coordinator) managedStatusLocked() ManagedInhibitionStatus {
	if c.managed == nil {
		return ManagedInhibitionStatus{}
	}
	data, _ := json.Marshal(c.managed.status)
	var status ManagedInhibitionStatus
	_ = json.Unmarshal(data, &status)
	return status
}

func (m *managedOverlay) prepare(compiled *CompiledManagedInhibition, generation uint64) (string, error) {
	if err := m.fault("prepare"); err != nil {
		return "", err
	}
	data, err := json.Marshal(managedOverlayFile{SchemaVersion: 1, Generation: generation, Rules: compiled.Definition.Rules})
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(m.path), ".oscar-inhibition-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := m.fault("write"); err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := m.fault("file_sync"); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := m.fault("close"); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func (m *managedOverlay) persist(name string) error {
	if err := m.fault("rename"); err != nil {
		return err
	}
	if err := os.Rename(name, m.path); err != nil {
		return err
	}
	if err := m.fault("directory_sync"); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(m.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// ApplyManagedInhibition replaces the full managed set, using ETag as the concurrency authority.
// A persistence error may follow successful activation; callers must inspect returned state.
func (c *Coordinator) ApplyManagedInhibition(etag string, input ManagedInhibitionSet) (ManagedInhibitionStatus, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	result := func(err error) (ManagedInhibitionStatus, error) { return c.managedStatusLocked(), err }
	m := c.managed
	if m == nil || c.base == nil {
		return result(managedError("unavailable", "Managed inhibition is not initialized."))
	}
	if etag == "" {
		return result(managedError("precondition_required", "If-Match is required."))
	}
	if etag != m.status.ETag {
		return result(managedError("precondition_failed", "Managed inhibition state changed; read status and desired state again."))
	}
	compiled, err := CompileManagedInhibition(input)
	if err != nil {
		return result(err)
	}
	candidate, err := mergeManaged(c.base, compiled)
	if err != nil {
		return result(err)
	}
	if len(c.subscribers) != 1 {
		return result(managedError("activation_failed", "Managed inhibition requires one transactional subscriber."))
	}
	changed := compiled.Digest != m.active.Digest
	generation := m.status.ActiveGeneration
	if changed {
		generation++
	}
	// Verify the disk on same-content requests, including lost responses and external removal.
	if !changed && m.status.ManagedFileHealthy {
		disk, diskGeneration, diskErr := readManagedOverlay(m.path)
		if diskErr == nil && disk.Digest == compiled.Digest && diskGeneration == generation {
			m.status.Error = nil
			return result(nil)
		}
	}
	if !changed {
		m.status.ManagedFileHealthy = false
		m.status.PersistedDigest = ""
		m.status.PersistedGeneration = 0
	}
	staged, err := m.prepare(compiled, generation)
	if err != nil {
		return result(c.managedFailure("persist_failed", "Managed rules could not be prepared for durable storage.", err))
	}
	defer os.Remove(staged)
	if changed {
		if err := c.notifySubscribers(candidate); err != nil {
			return result(c.managedFailure("activation_failed", "Managed rules could not be activated; inspect native service logs.", err))
		}
		c.config = candidate
		m.active = compiled
		m.status.ActiveDigest = compiled.Digest
		m.status.ActiveGeneration = generation
		m.status.Rules = compiled.Definition.Rules
		m.refreshETag()
	}
	if err := m.persist(staged); err != nil {
		m.status.ManagedFileHealthy = false
		m.status.PersistedDigest = ""
		m.status.PersistedGeneration = 0
		return result(c.managedFailure("persist_failed", "Managed rules are active but durability is unconfirmed; reconcile status before retrying.", err))
	}
	m.status.PersistedDigest = compiled.Digest
	m.status.PersistedGeneration = generation
	m.status.ManagedFileHealthy = true
	m.status.Error = nil
	return result(nil)
}
