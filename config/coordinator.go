// Copyright 2019 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/prometheus/alertmanager/eventrecorder"
)

// Coordinator coordinates Alertmanager configurations beyond the lifetime of a
// single configuration.
type Coordinator struct {
	configFilePath string
	logger         *slog.Logger

	// Protects config and subscribers
	mutex               sync.Mutex
	config              *Config
	base                *Config
	managed             *managedOverlay
	fixedObservation    *eventrecorder.WebhookOutputConfig
	observationRecorder eventrecorder.Recorder
	observationOnly     bool
	subscribers         []func(*Config) error

	configHashMetric        prometheus.Gauge
	configSuccessMetric     prometheus.Gauge
	configSuccessTimeMetric prometheus.Gauge
}

// NewCoordinator returns a new coordinator with the given configuration file
// path. It does not yet load the configuration from file. This is done in
// `Reload()`.
func NewCoordinator(configFilePath string, r prometheus.Registerer, l *slog.Logger) *Coordinator {
	c := &Coordinator{
		configFilePath: configFilePath,
		logger:         l,
	}

	c.registerMetrics(r)

	return c
}

func (c *Coordinator) registerMetrics(r prometheus.Registerer) {
	configHash := promauto.With(r).NewGauge(prometheus.GaugeOpts{
		Name: "alertmanager_config_hash",
		Help: "Hash of the currently loaded alertmanager configuration. Note that this is not a cryptographically strong hash.",
	})
	configSuccess := promauto.With(r).NewGauge(prometheus.GaugeOpts{
		Name: "alertmanager_config_last_reload_successful",
		Help: "Whether the last configuration reload attempt was successful.",
	})
	configSuccessTime := promauto.With(r).NewGauge(prometheus.GaugeOpts{
		Name: "alertmanager_config_last_reload_success_timestamp_seconds",
		Help: "Timestamp of the last successful configuration reload.",
	})

	c.configHashMetric = configHash
	c.configSuccessMetric = configSuccess
	c.configSuccessTimeMetric = configSuccessTime
}

// Subscribe subscribes the given Subscribers to configuration changes.
func (c *Coordinator) Subscribe(ss ...func(*Config) error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.subscribers = append(c.subscribers, ss...)
}

func (c *Coordinator) notifySubscribers(candidate *Config) error {
	if c.fixedObservation != nil {
		outputs := make([]eventrecorder.WebhookOutputConfig, 0, len(candidate.EventRecorder.WebhookOutputs)+1)
		for _, out := range candidate.EventRecorder.WebhookOutputs {
			if out.Name == eventrecorder.ObservationOutputName {
				if !eventrecorder.SameWebhookConfig(out, *c.fixedObservation) {
					return errors.New("reserved inhibition observation output conflict")
				}
				continue // Deduplicate an already-injected managed destination.
			}
			outputs = append(outputs, out)
		}
		if c.observationOnly {
			candidate.EventRecorder = eventrecorder.Config{}
			outputs = nil
		}
		candidate.EventRecorder.WebhookOutputs = append(outputs, *c.fixedObservation)
	}
	if c.observationOnly && c.fixedObservation == nil {
		candidate.EventRecorder = eventrecorder.Config{}
	}
	for _, s := range c.subscribers {
		if err := s(candidate); err != nil {
			return err
		}
	}

	return nil
}

// Reload triggers a configuration reload from file and notifies all
// configuration change subscribers.
func (c *Coordinator) Reload() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.logger.Info(
		"Loading configuration file",
		"file", c.configFilePath,
	)
	candidate, err := LoadFile(c.configFilePath)
	if err != nil {
		c.logger.Error(
			"Loading configuration file failed",
			"file", c.configFilePath,
			"err", err,
		)
		c.configSuccessMetric.Set(0)
		return err
	}
	c.logger.Info(
		"Completed loading of configuration file",
		"file", c.configFilePath,
	)

	if err := c.activateBaseLocked(candidate); err != nil {
		c.logger.Error(
			"one or more config change subscribers failed to apply new config",
			"file", c.configFilePath,
			"err", err,
		)
		c.configSuccessMetric.Set(0)
		return err
	}

	// Subscribers must stage fallible work before replacing live components.
	// Bookkeeping is committed only after activation succeeds.
	c.configSuccessMetric.Set(1)
	c.configSuccessTimeMetric.SetToCurrentTime()
	hash := md5HashAsMetricValue([]byte(c.config.original))
	c.configHashMetric.Set(hash)

	return nil
}

// ApplyConfig activates an already-loaded configuration and commits it only
// after all subscribers succeed.  Use this for the initial load so the file
// is only read once.
func (c *Coordinator) ApplyConfig(conf *Config) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if conf == nil {
		c.configSuccessMetric.Set(0)
		return errors.New("nil config passed to ApplyConfig")
	}

	if err := c.activateBaseLocked(conf); err != nil {
		c.logger.Error(
			"one or more config change subscribers failed to apply new config",
			"file", c.configFilePath,
			"err", err,
		)
		c.configSuccessMetric.Set(0)
		return err
	}

	c.configSuccessMetric.Set(1)
	c.configSuccessTimeMetric.SetToCurrentTime()
	hash := md5HashAsMetricValue([]byte(c.config.original))
	c.configHashMetric.Set(hash)

	return nil
}

func md5HashAsMetricValue(data []byte) float64 {
	sum := md5.Sum(data)
	// We only want 48 bits as a float64 only has a 53 bit mantissa.
	smallSum := sum[0:6]
	bytes := make([]byte, 8)
	copy(bytes, smallSum)
	return float64(binary.LittleEndian.Uint64(bytes))
}

// ConfigureObservations fixes sink configuration across base and managed-rule reloads.
// Called before first activation; the recorder remains long-lived across inhibitor rebuilds.
func (c *Coordinator) ConfigureObservations(recorder eventrecorder.Recorder, cfg eventrecorder.Config, observationOnly bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.observationRecorder = recorder
	c.observationOnly = observationOnly
	for _, out := range cfg.WebhookOutputs {
		if eventrecorder.IsManagedObservationOutput(out) {
			copy := out
			c.fixedObservation = &copy
		}
	}
}

// ObservationStatus reads recorder signals without scanning alerts or stored relationships.
func (c *Coordinator) ObservationStatus() map[string]any {
	return c.observationRecorder.ObservationStatus()
}
