package main

import (
	"context"
	"errors"
)

// The disconnected source is what the console runs on when it opens before
// a manager or a controller exists.
//
// Every read fails with the reason, so no page can show a fabricated PASS
// and no state can look healthy. The service operations stay usable through
// the CLI, which is how the runtime is recovered: initialize the
// controller, start the service, restart it.

// disconnectedSource answers every controller read with the same reason.
type disconnectedSource struct {
	reason string
}

// newDisconnectedSource returns a Source that cannot reach a controller.
// The reason is shown wherever the console needs the controller, so the
// console explains itself instead of looking idle.
func newDisconnectedSource(reason string) Source {
	if reason == "" {
		reason = "controller-unreachable"
	}
	return &disconnectedSource{reason: reason}
}

// failure is the one error this source reports.
func (d *disconnectedSource) failure() error { return errors.New(d.reason) }

func (d *disconnectedSource) Version() (VersionDoc, error) { return VersionDoc{}, d.failure() }

func (d *disconnectedSource) Configs() (ConfigsDoc, error) { return ConfigsDoc{}, d.failure() }

func (d *disconnectedSource) Proxies() (ProxiesDoc, error) { return ProxiesDoc{}, d.failure() }

func (d *disconnectedSource) Connections() (ConnectionsDoc, error) {
	return ConnectionsDoc{}, d.failure()
}

func (d *disconnectedSource) Rules() (RulesDoc, error) { return RulesDoc{}, d.failure() }

func (d *disconnectedSource) RuleProviders() (RuleProvidersDoc, error) {
	return RuleProvidersDoc{}, d.failure()
}

func (d *disconnectedSource) Memory() (MemoryDoc, error) { return MemoryDoc{}, d.failure() }

func (d *disconnectedSource) ProxyProviders() (ProxyProvidersDoc, error) {
	return ProxyProvidersDoc{}, d.failure()
}

func (d *disconnectedSource) Select(group, node string) error { return d.failure() }

func (d *disconnectedSource) DelayFor(provider, node string, timeoutMS int) (int, error) {
	return 0, d.failure()
}

func (d *disconnectedSource) Delay(node string, timeoutMS int) (int, error) {
	return 0, d.failure()
}

func (d *disconnectedSource) SetMode(mode string) error { return d.failure() }

func (d *disconnectedSource) RefreshProvider(name string) error { return d.failure() }

func (d *disconnectedSource) DNS(name, record string) (DNSAnswer, error) {
	return DNSAnswer{}, d.failure()
}

func (d *disconnectedSource) Download(url string) ([]byte, error) { return nil, d.failure() }

func (d *disconnectedSource) StartTraffic(ctx context.Context) (<-chan Traffic, error) {
	return nil, d.failure()
}

func (d *disconnectedSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return nil, d.failure()
}
