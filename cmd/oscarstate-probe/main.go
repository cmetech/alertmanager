// Copyright The Prometheus Authors
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

// Command oscarstate-probe runs an isolated native Alertmanager proof process.
// Both its API and its test notification receiver bind only to loopback.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/exporter-toolkit/web"

	"github.com/prometheus/alertmanager/app"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/oscarstate"
	"github.com/prometheus/alertmanager/oscarstate/memadapter"
	"github.com/prometheus/alertmanager/provider/mem"
)

type probeOptions struct {
	listen                                                            string
	gcInterval, resolveTimeout, groupWait, groupInterval, httpTimeout time.Duration
	getConcurrency, capacity                                          int
}

func defaultProbeOptions() probeOptions {
	return probeOptions{listen: "127.0.0.1:9093", gcInterval: 30 * time.Minute, resolveTimeout: 2 * time.Second, groupWait: 10 * time.Millisecond, groupInterval: 20 * time.Millisecond, httpTimeout: 5 * time.Second, getConcurrency: 4, capacity: 10000}
}

type probeProcess struct {
	app             *app.App
	feed            *oscarstate.Feed
	receipts        chan string
	receiver        *http.Server
	configPath, dir string
	cancel          context.CancelFunc
	heartbeatDone   chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

func startProbe(ctx context.Context, o probeOptions) (*probeProcess, error) {
	host, _, err := net.SplitHostPort(o.listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("listen must be a literal loopback address: %q", o.listen)
	}
	if o.capacity < 1 || o.gcInterval <= 0 || o.resolveTimeout <= 0 || o.groupWait <= 0 || o.groupInterval <= 0 || o.httpTimeout <= 0 || o.getConcurrency < 1 {
		return nil, fmt.Errorf("all limits and durations must be positive")
	}
	dir, err := os.MkdirTemp("", "oscarstate-proof-")
	if err != nil {
		return nil, err
	}
	p := &probeProcess{dir: dir, configPath: filepath.Join(dir, "alertmanager.yml"), feed: oscarstate.NewFeed(o.capacity, ""), receipts: make(chan string, 100), heartbeatDone: make(chan struct{})}
	cleanup := true
	defer func() {
		if cleanup {
			_ = p.Close(context.Background())
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	reg := prometheus.NewRegistry()
	received := prometheus.NewCounter(prometheus.CounterOpts{Name: "oscar_probe_notifications_total", Help: "Notifications received by the loopback-only proof receiver."})
	reg.MustRegister(received)
	p.receiver = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		received.Inc()
		select {
		case p.receipts <- string(body):
		default:
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = p.receiver.Serve(listener) }()
	cfg := fmt.Sprintf("global:\n  resolve_timeout: %s\nroute:\n  receiver: proof\n  group_by: [alertname]\n  group_wait: %s\n  group_interval: %s\n  repeat_interval: 1h\nreceivers:\n  - name: proof\n    webhook_configs:\n      - url: http://%s\n", o.resolveTimeout, o.groupWait, o.groupInterval, listener.Addr())
	if err := os.WriteFile(p.configPath, []byte(cfg), 0o600); err != nil {
		return nil, err
	}
	opts := app.DefaultOptions()
	opts.ConfigFile = p.configPath
	opts.DataDir = dir
	opts.AlertGCInterval = o.gcInterval
	opts.GetConcurrency = o.getConcurrency
	opts.HTTPTimeout = o.httpTimeout
	addrs := []string{o.listen}
	webConfig := ""
	opts.WebConfig = &web.FlagConfig{WebListenAddresses: &addrs, WebConfigFile: &webConfig}
	opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	opts.Registerer = reg
	opts.Flagger = featurecontrol.NoopFlags{}
	adapter := memadapter.New(p.feed)
	opts.StateObserver = adapter
	var provider *mem.Alerts
	opts.ProbeHandler = func(source *mem.Alerts) http.Handler {
		provider = source
		probe := oscarstate.NewProbeHandler(func() oscarstate.Snapshot { return adapter.Snapshot(source) }, p.feed)
		metrics := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil || !net.ParseIP(host).IsLoopback() {
				http.Error(w, "loopback only", http.StatusForbidden)
				return
			}
			if r.URL.Path == "/_oscar/probe/metrics" {
				metrics.ServeHTTP(w, r)
				return
			}
			probe.ServeHTTP(w, r)
		})
	}
	p.app, err = app.New(opts)
	if err != nil {
		return nil, err
	}
	if err = p.app.Start(); err != nil {
		return nil, err
	}
	cadence := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "oscar_probe_heartbeat_cadence_seconds", Help: "Actual interval between provider heartbeat attempts.", Buckets: []float64{0.9, 1, 1.1, 1.5, 2, 5}})
	reg.MustRegister(cadence)
	heartbeatCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go func() {
		defer close(p.heartbeatDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		last := time.Now()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				cadence.Observe(now.Sub(last).Seconds())
				last = now
				provider.TryHeartbeat(100 * time.Millisecond)
			}
		}
	}()
	cleanup = false
	return p, nil
}

func (p *probeProcess) Close(ctx context.Context) error {
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
			<-p.heartbeatDone
		}
		if p.app != nil {
			p.closeErr = p.app.Stop(ctx)
		}
		if p.receiver != nil {
			if err := p.receiver.Shutdown(ctx); p.closeErr == nil {
				p.closeErr = err
			}
		}
		if err := os.RemoveAll(p.dir); p.closeErr == nil {
			p.closeErr = err
		}
	})
	return p.closeErr
}

func main() {
	opts := defaultProbeOptions()
	flag.StringVar(&opts.listen, "listen", opts.listen, "Literal loopback API listen address")
	flag.DurationVar(&opts.gcInterval, "alert-gc-interval", opts.gcInterval, "Native provider GC interval (short trials: <=1s)")
	flag.DurationVar(&opts.resolveTimeout, "resolve-timeout", opts.resolveTimeout, "Native implicit resolution timeout")
	flag.DurationVar(&opts.groupWait, "group-wait", opts.groupWait, "Test notification group wait")
	flag.DurationVar(&opts.groupInterval, "group-interval", opts.groupInterval, "Test notification group interval")
	flag.DurationVar(&opts.httpTimeout, "http-timeout", opts.httpTimeout, "Native API GET timeout")
	flag.IntVar(&opts.getConcurrency, "get-concurrency", opts.getConcurrency, "Native API concurrent GET limit")
	flag.IntVar(&opts.capacity, "feed-capacity", opts.capacity, "Bounded retained change count")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p, err := startProbe(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"addr": p.app.Addr(), "epoch": p.feed.Cursor().Epoch, "config": p.configPath, "gcInterval": opts.gcInterval.String(), "resolveTimeout": opts.resolveTimeout.String(), "groupWait": opts.groupWait.String(), "groupInterval": opts.groupInterval.String(), "getConcurrency": opts.getConcurrency, "httpTimeout": opts.httpTimeout.String()})
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case <-reload:
			if err := p.app.Reload(); err != nil {
				slog.Error("proof reload failed", "err", err)
			}
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Close(shutdown); err != nil {
		slog.Error("proof shutdown failed", "err", err)
	}
}
