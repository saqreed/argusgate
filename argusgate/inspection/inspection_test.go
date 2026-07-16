package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInspectListsMetadataWithoutCallingOrReading(t *testing.T) {
	server := sdk.NewServer(
		&sdk.Implementation{Name: "test-server", Version: "1.0.0"},
		&sdk.ServerOptions{Instructions: "Review metadata", PageSize: 1},
	)
	var called atomic.Bool
	for _, name := range []string{"read_file", "list_files"} {
		server.AddTool(&sdk.Tool{
			Name: name, Description: "Read files safely",
			InputSchema: map[string]any{"type": "object"},
		}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			called.Store(true)
			return nil, errors.New("tool calls are forbidden in this test")
		})
	}
	server.AddPrompt(&sdk.Prompt{Name: "review", Description: "Review metadata"}, func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		called.Store(true)
		return nil, errors.New("prompt reads are forbidden in this test")
	})
	server.AddResource(&sdk.Resource{Name: "docs", URI: "file:///docs"}, func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		called.Store(true)
		return nil, errors.New("resource reads are forbidden in this test")
	})
	server.AddResourceTemplate(&sdk.ResourceTemplate{Name: "files", URITemplate: "file:///{path}"}, func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		called.Store(true)
		return nil, errors.New("resource reads are forbidden in this test")
	})

	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{JSONResponse: true})
	var mutex sync.Mutex
	var methods []string
	recording := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(raw))
			var message struct {
				Method string `json:"method"`
			}
			if jsonErr := json.Unmarshal(raw, &message); jsonErr != nil {
				t.Error(jsonErr)
				return
			}
			mutex.Lock()
			methods = append(methods, message.Method)
			mutex.Unlock()
		}
		handler.ServeHTTP(response, request)
	})
	httpServer := httptest.NewTLSServer(recording)
	defer httpServer.Close()

	doc, err := inspectWithTransport(context.Background(), Options{
		URL: httpServer.URL, ServerID: "test", Timeout: 10 * time.Second, ClientVersion: "0.3.0",
	}, httpServer.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Tools) != 2 || len(doc.Prompts) != 1 || len(doc.Resources) != 1 || len(doc.ResourceTemplates) != 1 {
		t.Fatalf("unexpected metadata counts: tools=%d prompts=%d resources=%d templates=%d", len(doc.Tools), len(doc.Prompts), len(doc.Resources), len(doc.ResourceTemplates))
	}
	if called.Load() {
		t.Fatal("inspection invoked a tool, prompt, or resource handler")
	}
	allowed := map[string]bool{
		"initialize": true, "notifications/initialized": true,
		"tools/list": true, "prompts/list": true, "resources/list": true, "resources/templates/list": true,
	}
	for _, method := range methods {
		if !allowed[method] {
			t.Fatalf("unexpected MCP method %q in %v", method, methods)
		}
	}
}

func TestValidateEndpointAndHeaders(t *testing.T) {
	for _, endpoint := range []string{
		"http://example.test/mcp",
		"https://user:password@example.test/mcp",
		"https://example.test/mcp#fragment",
		"https://example.test/mcp?token=secret",
	} {
		if _, err := validateEndpoint(endpoint); err == nil {
			t.Fatalf("validateEndpoint(%q) succeeded", endpoint)
		}
	}
	if _, err := validateEndpoint("https://example.test/mcp?tenant=test"); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ARGUS_TOKEN", "FAKE_TOKEN_DO_NOT_USE")
	t.Setenv("ARGUS_KEY", "FAKE_KEY_DO_NOT_USE")
	headers, err := resolveHeaders("ARGUS_TOKEN", []string{"X-API-Key=ARGUS_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if headers.Get("Authorization") != "Bearer FAKE_TOKEN_DO_NOT_USE" || headers.Get("X-API-Key") != "FAKE_KEY_DO_NOT_USE" {
		t.Fatalf("unexpected headers: %v", headers)
	}
	if _, err := resolveHeaders("", []string{"Host=ARGUS_KEY"}); err == nil {
		t.Fatal("Host header was accepted")
	}
}

func TestEndpointForMetadataRedactsEveryQueryValue(t *testing.T) {
	endpoint, err := url.Parse("https://example.test/mcp?tenant=customer-secret&tenant=second-secret&mode=review")
	if err != nil {
		t.Fatal(err)
	}
	metadataEndpoint := endpointForMetadata(endpoint)
	if strings.Contains(metadataEndpoint, "customer-secret") || strings.Contains(metadataEndpoint, "second-secret") {
		t.Fatalf("metadata endpoint exposed query values: %s", metadataEndpoint)
	}
	if !strings.Contains(metadataEndpoint, "tenant=") || !strings.Contains(metadataEndpoint, "mode=") {
		t.Fatalf("metadata endpoint lost query parameter names: %s", metadataEndpoint)
	}
	if endpoint.Query().Get("tenant") != "customer-secret" {
		t.Fatal("metadata redaction modified the connection endpoint")
	}
}

func TestSecureTransportBlocksToolCalls(t *testing.T) {
	called := false
	transport := &secureRoundTripper{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`)),
				Header:     make(http.Header),
			}, nil
		}),
		origin: "https://example.test", maxBytes: MaxResponseBytes,
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "blocked method") {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("blocked request reached the network transport")
	}
}

func TestSecureTransportReplacesCredentialHeaders(t *testing.T) {
	transport := &secureRoundTripper{
		base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if got := request.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer safe-env-value" {
				t.Fatalf("unexpected Authorization headers: %#v", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`)),
				Header:     make(http.Header),
			}, nil
		}),
		origin:   "https://example.test",
		headers:  http.Header{"Authorization": []string{"Bearer safe-env-value"}},
		maxBytes: MaxResponseBytes,
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Authorization", "Bearer attacker-controlled")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}

func TestLimitedReadCloserDoesNotReturnBytesBeyondLimit(t *testing.T) {
	reader := &limitedReadCloser{
		reader: strings.NewReader("123456"),
		closer: io.NopCloser(strings.NewReader("")),
		limit:  5,
	}
	buffer := make([]byte, 8)
	count, err := reader.Read(buffer)
	if err == nil || count != 5 || string(buffer[:count]) != "12345" {
		t.Fatalf("unexpected limited read: count=%d err=%v data=%q", count, err, buffer[:count])
	}
}

func TestLimitedReadCloserEnforcesSessionBudget(t *testing.T) {
	budget := &responseBudget{remaining: 4}
	reader := &limitedReadCloser{
		reader: strings.NewReader("123456"),
		closer: io.NopCloser(strings.NewReader("")),
		limit:  10,
		budget: budget,
	}
	buffer := make([]byte, 8)
	count, err := reader.Read(buffer)
	if err == nil || count != 4 || string(buffer[:count]) != "1234" {
		t.Fatalf("unexpected budgeted read: count=%d err=%v data=%q", count, err, buffer[:count])
	}
}

func TestPaginateRejectsRepeatedCursor(t *testing.T) {
	calls := 0
	err := paginate("tools/list", func(string) (string, error) {
		calls++
		return "same", nil
	})
	if err == nil || !strings.Contains(err.Error(), "repeated") || calls != 2 {
		t.Fatalf("unexpected result: calls=%d err=%v", calls, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
