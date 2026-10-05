package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/saqreed/argusgate/argusgate/mcp"
)

func TestSecurityInspectionDoesNotExposeRemoteErrorText(t *testing.T) {
	const fake = "FAKE OPAQUE CREDENTIAL DO NOT USE"
	t.Setenv("ARGUS_FAKE_KEY", fake)
	for _, method := range []string{"initialize", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			server := sdk.NewServer(&sdk.Implementation{Name: "test", Version: "test"}, nil)
			server.AddTool(&sdk.Tool{Name: "read", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				return nil, errors.New("must not call")
			})
			handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{JSONResponse: true})
			tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					raw, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(raw))
					var msg struct {
						Method string          `json:"method"`
						ID     json.RawMessage `json:"id"`
					}
					if err := json.Unmarshal(raw, &msg); err != nil {
						t.Error(err)
						return
					}
					if msg.Method == method {
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": map[string]any{"code": -32603, "message": r.Header.Get("X-API-Key")}})
						return
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer tls.Close()
			_, err := inspectWithTransport(context.Background(), Options{URL: tls.URL, HeaderEnv: []string{"X-API-Key=ARGUS_FAKE_KEY"}, Timeout: 5 * time.Second}, tls.Client().Transport)
			if err == nil {
				t.Fatal("expected inspection error")
			}
			if strings.Contains(err.Error(), fake) {
				t.Fatalf("remote credential echo reached diagnostic: %q", err)
			}
		})
	}
}

func TestSecurityInspectionRejectsMalformedQueryAndHeader(t *testing.T) {
	for _, endpoint := range []string{"https://example.test/mcp?token=FAKE%zz", "https://example.test/mcp?token=FAKE;tenant=x"} {
		if _, err := validateEndpoint(endpoint); err == nil {
			t.Errorf("malformed query accepted: %s", endpoint)
		}
	}
	t.Setenv("ARGUS_FAKE_TOKEN", "FAKE\r\nHEADER_DO_NOT_USE")
	if _, err := resolveHeaders("ARGUS_FAKE_TOKEN", nil); err == nil {
		t.Fatal("bearer header line break accepted")
	}
}

func TestSecurityToMapPreservesLargeIntegers(t *testing.T) {
	left := toMap(map[string]any{"limit": uint64(9007199254740992)})
	right := toMap(map[string]any{"limit": uint64(9007199254740993)})
	a, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("large numeric schema values collapsed during inspection conversion")
	}
}

func TestSecurityInspectionRejectsLossyNumbers(t *testing.T) {
	for _, number := range []any{float64(9007199254740992), json.Number("9007199254740993")} {
		if err := validateLiveNumbers(mcp.Document{Tools: []mcp.ToolDefinition{{InputSchema: map[string]any{"limit": number}}}}); err == nil {
			t.Fatal("SDK-imprecise number accepted")
		}
	}
	if err := validateLiveNumbers(mcp.Document{Tools: []mcp.ToolDefinition{{InputSchema: map[string]any{"limit": json.Number("9007199254740991")}}}}); err != nil {
		t.Fatal(err)
	}
}
