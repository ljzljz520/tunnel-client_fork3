package mcpclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/fx"
	"golang.org/x/sync/singleflight"

	"github.com/openai/tunnel-client/pkg/credrotation"
	tclog "github.com/openai/tunnel-client/pkg/log"
	"github.com/openai/tunnel-client/pkg/proxy"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tlsconfig"
)

// ChannelTransportFactory builds and caches MCP transports for configured
// channel bindings.
//
// A connector request can arrive on any logical tunnel-service channel. The
// dispatcher asks this factory for the binding-specific transport, and the
// factory keeps one cached transport/HTTP client per channel so session headers,
// proxy selection, mTLS config, and raw-HTTP logging remain stable across
// requests for that channel.
type ChannelTransportFactory struct {
	config        *runtimeconfig.MCPConfig
	logger        *slog.Logger
	logging       *runtimeconfig.LoggingConfig
	providers     []TransportProvider
	meterProvider *sdkmetric.MeterProvider
	tlsBundle     *tlsconfig.Bundle

	// rotationCtx drives per-channel credential pollers. It is cancelled on
	// shutdown so all rotation goroutines stop together.
	rotationCtx    context.Context
	rotationCancel context.CancelFunc

	mu          sync.Mutex
	transports  map[string]mcp.Transport
	httpClients map[string]*http.Client
	rotators    map[string]*credentialRotator

	transportGroup  singleflight.Group
	httpClientGroup singleflight.Group
}

type channelTransportFactoryParams struct {
	fx.In

	Config             *runtimeconfig.MCPConfig
	Logging            *runtimeconfig.LoggingConfig
	Logger             *slog.Logger
	MeterProvider      *sdkmetric.MeterProvider
	TLSBundle          *tlsconfig.Bundle
	TransportProviders []TransportProvider `group:"mcp_transport_providers"`
	Lifecycle          fx.Lifecycle        `optional:"true"`
}

var errCrossOriginRuntimeMCPRedirect = errors.New("mcpclient: redirect blocked: destination must use the configured MCP origin")

func newChannelTransportFactory(p channelTransportFactoryParams) (*ChannelTransportFactory, error) {
	if p.Config == nil || p.Logging == nil || p.Logger == nil || p.MeterProvider == nil {
		return nil, fmt.Errorf("mcpclient: channel transport factory requires config, logging, logger, and meter provider")
	}
	rotationCtx, rotationCancel := context.WithCancel(context.Background())
	factory := &ChannelTransportFactory{
		config:         p.Config,
		logger:         p.Logger,
		logging:        p.Logging,
		meterProvider:  p.MeterProvider,
		tlsBundle:      p.TLSBundle,
		providers:      p.TransportProviders,
		rotationCtx:    rotationCtx,
		rotationCancel: rotationCancel,
		transports:     make(map[string]mcp.Transport),
		httpClients:    make(map[string]*http.Client),
		rotators:       make(map[string]*credentialRotator),
	}
	if p.Lifecycle != nil {
		p.Lifecycle.Append(fx.Hook{
			OnStop: func(context.Context) error {
				factory.stopCredentialRotation()
				return nil
			},
		})
	}
	factory.logProxyConfig()
	return factory, nil
}

// stopCredentialRotation stops every credential poller and closes rotated
// generations' idle connections. Safe to call multiple times.
func (f *ChannelTransportFactory) stopCredentialRotation() {
	if f == nil {
		return
	}
	f.rotationCancel()
	f.mu.Lock()
	rotators := f.rotators
	f.rotators = make(map[string]*credentialRotator)
	f.mu.Unlock()
	for _, rotator := range rotators {
		rotator.closeAll()
	}
}

// HTTPClientForBinding returns the shared HTTP client for a binding. OAuth
// discovery uses this client directly so it can keep its own redirect policy.
// Runtime streamable MCP transports use a shallow copy with the stricter
// configured-origin redirect boundary installed by runtimeHTTPClientForBinding.
func (f *ChannelTransportFactory) HTTPClientForBinding(binding runtimeconfig.MCPChannelBinding) (*http.Client, error) {
	if f == nil {
		return nil, fmt.Errorf("mcpclient: channel transport factory is nil")
	}
	transportKind := binding.TransportKind
	if transportKind == "" {
		transportKind = runtimeconfig.MCPTransportHTTPStreamable
	}
	if transportKind != runtimeconfig.MCPTransportHTTPStreamable {
		return f.httpClientForKey("default", nil)
	}
	channelName := binding.Channel.Canonical()
	if channelName == "" {
		return nil, fmt.Errorf("mcpclient: invalid channel name")
	}
	return f.httpClientForKey(channelName.String(), &binding)
}

// runtimeHTTPClientForBinding returns the HTTP client used by streamable MCP
// runtime traffic. Redirects are checked before the next RoundTrip so a
// cross-origin 3xx response cannot re-send request headers, methods, or bodies
// through the forwarding transport.
func (f *ChannelTransportFactory) runtimeHTTPClientForBinding(binding runtimeconfig.MCPChannelBinding) (*http.Client, error) {
	client, err := f.HTTPClientForBinding(binding)
	if err != nil {
		return nil, err
	}
	transportKind := binding.TransportKind
	if transportKind == "" {
		transportKind = runtimeconfig.MCPTransportHTTPStreamable
	}
	if transportKind != runtimeconfig.MCPTransportHTTPStreamable {
		return client, nil
	}
	if binding.ServerURL == nil {
		return nil, fmt.Errorf("mcpclient: server URL is required for %s transport", transportKind)
	}
	return withRuntimeMCPRedirectPolicy(client, binding.ServerURL), nil
}

// withRuntimeMCPRedirectPolicy returns a shallow copy so the runtime MCP
// redirect boundary does not alter the shared client used by OAuth discovery.
// The configured origin is checked on every hop, while same-origin redirects
// retain the standard library's default ten-hop limit.
func withRuntimeMCPRedirectPolicy(client *http.Client, configuredOrigin *url.URL) *http.Client {
	if client == nil {
		return nil
	}
	cloned := *client
	priorPolicy := client.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req == nil || !sameURLOrigin(req.URL, configuredOrigin) {
			return errCrossOriginRuntimeMCPRedirect
		}
		if priorPolicy != nil {
			return priorPolicy(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("mcpclient: stopped after %d redirects", len(via))
		}
		return nil
	}
	return &cloned
}

// Build returns a cached transport for the requested binding. Concurrent first
// use of the same channel is collapsed with singleflight so duplicate connector
// traffic cannot race into multiple stdio child processes or independent HTTP
// transport wrappers.
func (f *ChannelTransportFactory) Build(binding runtimeconfig.MCPChannelBinding) (mcp.Transport, error) {
	if f == nil {
		return nil, fmt.Errorf("mcpclient: channel transport factory is nil")
	}
	channelName := binding.Channel.Canonical()
	if channelName == "" {
		return nil, fmt.Errorf("mcpclient: invalid channel name")
	}

	f.mu.Lock()
	if transport, ok := f.transports[channelName.String()]; ok {
		f.mu.Unlock()
		return transport, nil
	}
	f.mu.Unlock()

	result, err, _ := f.transportGroup.Do(channelName.String(), func() (any, error) {
		f.mu.Lock()
		if transport, ok := f.transports[channelName.String()]; ok {
			f.mu.Unlock()
			return transport, nil
		}
		f.mu.Unlock()

		transportKind := binding.TransportKind
		if transportKind == "" {
			transportKind = runtimeconfig.MCPTransportHTTPStreamable
		}
		provider, err := selectTransportProvider(transportKind, f.providers)
		if err != nil {
			return nil, err
		}
		httpClient, err := f.runtimeHTTPClientForBinding(binding)
		if err != nil {
			return nil, err
		}
		transport, err := provider.Build(TransportBuildParams{
			Config:     f.config,
			Binding:    binding,
			HTTPClient: httpClient,
		})
		if err != nil {
			return nil, err
		}
		transport = f.decorateTransport(transport)

		f.mu.Lock()
		f.transports[channelName.String()] = transport
		f.mu.Unlock()

		return transport, nil
	})
	if err != nil {
		return nil, err
	}
	transport, ok := result.(mcp.Transport)
	if !ok {
		return nil, fmt.Errorf("mcpclient: unexpected transport type %T", result)
	}
	return transport, nil
}

func (f *ChannelTransportFactory) decorateTransport(base mcp.Transport) mcp.Transport {
	if base == nil {
		return nil
	}
	if f.logging == nil || !f.logging.HTTPRawUnsafe || f.logging.Level > slog.LevelDebug {
		return base
	}
	logger := f.logger.With(tclog.FieldComponent, tclog.ComponentMcpClient, "transport", "raw_http")
	return &mcp.LoggingTransport{
		Transport: base,
		Writer:    slogWriter{logger: logger},
	}
}

// httpClientForKey returns the cached HTTP client for one channel, building
// the per-channel transport stack on first use. When credential rotation is
// enabled for the binding, a generation manager is created and started; its
// initial all-or-nothing load failing makes construction fail closed.
func (f *ChannelTransportFactory) httpClientForKey(key string, binding *runtimeconfig.MCPChannelBinding) (*http.Client, error) {
	f.mu.Lock()
	if client, ok := f.httpClients[key]; ok {
		f.mu.Unlock()
		return client, nil
	}
	f.mu.Unlock()
	result, err, _ := f.httpClientGroup.Do(key, func() (any, error) {
		f.mu.Lock()
		if client, ok := f.httpClients[key]; ok {
			f.mu.Unlock()
			return client, nil
		}
		f.mu.Unlock()

		var (
			serverURL         *url.URL
			unixSocketPath    string
			proxyURL          *url.URL
			clientCertificate *tlsconfig.ClientCertificate
		)
		if binding != nil {
			serverURL = binding.ServerURL
			unixSocketPath = binding.UnixSocketPath
			proxyURL = binding.HTTPProxy
			clientCertificate = binding.ClientCertificate
		}

		var manager *credrotation.Manager
		if binding != nil {
			if spec, ok := f.config.CredentialRotationSpec(*binding); ok {
				loader, err := credrotation.NewLoader(spec)
				if err != nil {
					return nil, fmt.Errorf("mcpclient: credential rotation for channel %q: %w", key, err)
				}
				manager, err = credrotation.NewManager(
					f.logger.With(tclog.FieldComponent, tclog.ComponentMcpClient, "channel", key),
					loader,
					credrotation.WithPollInterval(f.config.CredentialRotation.PollInterval),
				)
				if err != nil {
					return nil, fmt.Errorf("mcpclient: credential rotation for channel %q: %w", key, err)
				}
			}
		}

		transport, rotator, err := buildMcpHTTPTransport(mcpHTTPTransportParams{
			Logger:                f.logger,
			LoggingConfig:         f.logging,
			MeterProvider:         f.meterProvider,
			TLSBundle:             f.tlsBundle,
			ClientCertificate:     clientCertificate,
			UnixSocketPath:        unixSocketPath,
			ProxyURL:              proxyURL,
			ServerURL:             serverURL,
			ExtraHeaders:          f.config.ExtraHeaders,
			DiscoveryExtraHeaders: f.config.DiscoveryExtraHeaders,
			LocalTracing:          f.config.TraceContextEnabled,
			RotationManager:       manager,
		})
		if err != nil {
			return nil, err
		}
		client := &http.Client{Transport: transport}
		f.mu.Lock()
		f.httpClients[key] = client
		if rotator != nil {
			f.rotators[key] = rotator
		}
		f.mu.Unlock()
		if manager != nil {
			go manager.Run(f.rotationCtx)
		}
		return client, nil
	})
	if err != nil {
		return nil, err
	}
	client, ok := result.(*http.Client)
	if !ok {
		return nil, fmt.Errorf("mcpclient: unexpected http client type %T", result)
	}
	return client, nil
}

func (f *ChannelTransportFactory) logProxyConfig() {
	if f == nil || f.logger == nil || f.config == nil {
		return
	}
	logger := f.logger.With(tclog.FieldComponent, tclog.ComponentMcpClient)
	for _, binding := range f.config.ChannelBindings {
		channel := binding.Channel.Canonical()
		transportKind := binding.TransportKind
		if transportKind == "" {
			transportKind = runtimeconfig.MCPTransportHTTPStreamable
		}
		var targetURL *url.URL
		if transportKind == runtimeconfig.MCPTransportHTTPStreamable {
			targetURL = binding.ServerURL
		}
		route := proxy.ResolveRoute(proxy.RouteKindMCPChannel, channel.String(), targetURL, binding.HTTPProxy, binding.HTTPProxySource, os.LookupEnv)
		fields := []any{
			slog.String("channel", channel.String()),
			slog.String("transport", string(transportKind)),
			slog.Bool("mtls_enabled", binding.ClientCertificate != nil),
			slog.String("route_kind", string(route.Kind)),
			slog.String("route_name", route.Name),
			slog.String("target_host", route.TargetHostPort),
		}
		if binding.ClientCertificate != nil {
			fields = append(fields, slog.String("mtls_cert_path", binding.ClientCertificate.CertPath))
		}
		if binding.UnixSocketPath != "" {
			fields = append(fields, slog.String("unix_socket_path", binding.UnixSocketPath))
		}
		fields = append(fields, proxy.LogFields(route)...)
		logger.Info("mcp channel route resolved", fields...)
	}
}
