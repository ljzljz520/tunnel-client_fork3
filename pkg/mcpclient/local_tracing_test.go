package mcpclient

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

func TestLocalTracingDoesNotInjectGlobalHTTPContext(t *testing.T) {
	original := otel.GetTextMapPropagator()
	if len(original.Fields()) == 0 {
		original = propagation.NewCompositeTextMapPropagator()
	}
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() { otel.SetTextMapPropagator(original) })
	headers := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers <- request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	for _, enabled := range []bool{false, true} {
		transport, _, err := buildMcpHTTPTransport(mcpHTTPTransportParams{
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			LoggingConfig: &runtimeconfig.LoggingConfig{},
			MeterProvider: sdkmetric.NewMeterProvider(),
			ServerURL:     mustParseURL(t, server.URL),
			LocalTracing:  enabled,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx := otel.GetTextMapPropagator().Extract(context.Background(), propagation.MapCarrier{
			"traceparent": "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
			"tracestate":  "private=secret", "baggage": "private=prompt",
		})
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		observed := <-headers
		for _, name := range []string{"traceparent", "tracestate", "baggage"} {
			if (observed.Get(name) == "") != enabled {
				t.Fatalf("enabled=%v unexpected %s header: %q", enabled, name, observed.Get(name))
			}
		}
		if enabled {
			request.Header.Set("traceparent", "caller-owned")
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if (<-headers).Get("traceparent") != "caller-owned" {
				t.Fatal("caller-owned header changed")
			}
		}
	}
}
