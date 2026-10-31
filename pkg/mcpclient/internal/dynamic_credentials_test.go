package internal

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openai/tunnel-client/pkg/credrotation"
	"github.com/openai/tunnel-client/pkg/headerscope"
)

func TestDynamicCredentialRoundTripperPinsSnapshotAndHeaders(t *testing.T) {
	t.Parallel()

	serverURL := mustParseURL(t, "https://mcp.example.test/mcp")

	first := &credrotation.Snapshot{
		ExtraHeaders:          map[string]string{"Authorization": "Bearer gen-1"},
		DiscoveryExtraHeaders: map[string]string{"X-Discovery-Auth": "disc-1"},
	}
	second := &credrotation.Snapshot{
		ExtraHeaders:          map[string]string{"Authorization": "Bearer gen-2"},
		DiscoveryExtraHeaders: map[string]string{"X-Discovery-Auth": "disc-2"},
	}
	current := first

	var pinned []*credrotation.Snapshot
	var seen []http.Header
	rt := NewDynamicCredentialRoundTripper(
		roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			pinned = append(pinned, CredentialSnapshotFromContext(req.Context()))
			seen = append(seen, req.Header.Clone())
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}),
		serverURL,
		func() *credrotation.Snapshot { return current },
	)

	runtimeReq := mustRequest(t, context.Background(), "https://mcp.example.test/mcp")
	if _, err := rt.RoundTrip(runtimeReq); err != nil {
		t.Fatalf("runtime RoundTrip: %v", err)
	}
	discoveryReq := mustRequest(t, headerscope.WithMCPDiscovery(context.Background()), "https://mcp.example.test/.well-known/oauth-protected-resource/mcp")
	if _, err := rt.RoundTrip(discoveryReq); err != nil {
		t.Fatalf("discovery RoundTrip: %v", err)
	}

	current = second
	rotatedReq := mustRequest(t, context.Background(), "https://mcp.example.test/mcp")
	if _, err := rt.RoundTrip(rotatedReq); err != nil {
		t.Fatalf("rotated RoundTrip: %v", err)
	}

	crossOriginReq := mustRequest(t, context.Background(), "https://auth.example.test/token")
	if _, err := rt.RoundTrip(crossOriginReq); err != nil {
		t.Fatalf("cross-origin RoundTrip: %v", err)
	}

	if len(seen) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(seen))
	}
	for i, snapshot := range pinned {
		if snapshot == nil {
			t.Fatalf("request %d had no pinned snapshot", i)
		}
	}
	if got := seen[0].Get("Authorization"); got != "Bearer gen-1" {
		t.Fatalf("gen1 runtime Authorization = %q", got)
	}
	if got := seen[0].Get("X-Discovery-Auth"); got != "" {
		t.Fatalf("runtime request leaked discovery header %q", got)
	}
	if got := seen[1].Get("Authorization"); got != "Bearer gen-1" {
		t.Fatalf("gen1 discovery Authorization = %q", got)
	}
	if got := seen[1].Get("X-Discovery-Auth"); got != "disc-1" {
		t.Fatalf("gen1 discovery header = %q", got)
	}
	if got := seen[2].Get("Authorization"); got != "Bearer gen-2" {
		t.Fatalf("gen2 runtime Authorization = %q", got)
	}
	if pinned[2] != second {
		t.Fatalf("rotated request pinned the wrong snapshot")
	}
	if got := seen[3].Get("Authorization"); got != "" {
		t.Fatalf("cross-origin request received credential header %q", got)
	}
	if pinned[3] != second {
		t.Fatalf("cross-origin request must still pin a snapshot for the selector")
	}
}

func TestDynamicCredentialRoundTripperPinsCertificateOnlyGeneration(t *testing.T) {
	t.Parallel()

	serverURL := mustParseURL(t, "https://mcp.example.test/mcp")
	snapshot := &credrotation.Snapshot{} // certificate-only generations have no headers

	called := false
	rt := NewDynamicCredentialRoundTripper(
		roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			if CredentialSnapshotFromContext(req.Context()) == nil {
				t.Fatalf("certificate-only generation was not pinned to the request")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}),
		serverURL,
		func() *credrotation.Snapshot { return snapshot },
	)

	req := mustRequest(t, context.Background(), "https://mcp.example.test/mcp")
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if !called {
		t.Fatalf("base RoundTripper not called")
	}
}

func TestCredentialSnapshotContextAccessors(t *testing.T) {
	t.Parallel()

	if got := CredentialSnapshotFromContext(context.Background()); got != nil {
		t.Fatalf("expected nil snapshot from empty context")
	}
	snapshot := &credrotation.Snapshot{}
	ctx := WithCredentialSnapshot(context.Background(), snapshot)
	if CredentialSnapshotFromContext(ctx) != snapshot {
		t.Fatalf("pinned snapshot did not round-trip through context")
	}
	if WithCredentialSnapshot(ctx, nil) != ctx {
		t.Fatalf("nil snapshot should not replace an existing context")
	}
}
