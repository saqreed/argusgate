package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
)

const (
	DefaultTimeout   = 15 * time.Second
	MinTimeout       = time.Second
	MaxTimeout       = 2 * time.Minute
	MaxResponseBytes = int64(16 << 20)
	MaxSessionBytes  = int64(64 << 20)
	MaxRequestBytes  = int64(1 << 20)
	MaxPages         = 100
)

type Options struct {
	URL           string
	ServerID      string
	Timeout       time.Duration
	TokenEnv      string
	HeaderEnv     []string
	ClientVersion string
}

func Inspect(ctx context.Context, options Options) (mcp.Document, error) {
	return inspectWithTransport(ctx, options, http.DefaultTransport)
}

func inspectWithTransport(ctx context.Context, options Options, base http.RoundTripper) (mcp.Document, error) {
	endpoint, err := validateEndpoint(options.URL)
	if err != nil {
		return mcp.Document{}, err
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Timeout < MinTimeout || options.Timeout > MaxTimeout {
		return mcp.Document{}, fmt.Errorf("inspection timeout must be between %s and %s", MinTimeout, MaxTimeout)
	}
	headers, err := resolveHeaders(options.TokenEnv, options.HeaderEnv)
	if err != nil {
		return mcp.Document{}, err
	}
	if strings.TrimSpace(options.ServerID) == "" {
		options.ServerID = endpoint.Hostname()
	}

	roundTripper := &secureRoundTripper{
		base:     base,
		origin:   endpoint.Scheme + "://" + endpoint.Host,
		headers:  headers,
		maxBytes: MaxResponseBytes,
		budget:   &responseBudget{remaining: MaxSessionBytes},
	}
	httpClient := &http.Client{
		Transport: roundTripper,
		Timeout:   options.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("HTTP redirects are disabled for MCP inspection")
		},
	}
	client := sdk.NewClient(
		&sdk.Implementation{Name: "argusgate", Version: options.ClientVersion},
		&sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}},
	)
	transport := &sdk.StreamableClientTransport{
		Endpoint:             endpoint.String(),
		HTTPClient:           httpClient,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}

	sessionCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	metadataEndpoint := endpointForMetadata(endpoint)
	session, err := client.Connect(sessionCtx, transport, nil)
	if err != nil {
		return mcp.Document{}, fmt.Errorf(
			"connect to MCP endpoint %s: %s",
			metadataEndpoint,
			redact.Text(strings.ReplaceAll(err.Error(), endpoint.String(), metadataEndpoint)),
		)
	}
	defer session.Close()

	initialize := session.InitializeResult()
	if initialize == nil {
		return mcp.Document{}, errors.New("MCP endpoint did not return initialize metadata")
	}
	server := mcp.ServerConfig{
		ID:              options.ServerID,
		URL:             metadataEndpoint,
		Transport:       "streamable-http",
		ProtocolVersion: initialize.ProtocolVersion,
		Instructions:    initialize.Instructions,
		Capabilities:    toMap(initialize.Capabilities),
	}
	if initialize.ServerInfo != nil {
		server.Name = initialize.ServerInfo.Name
		server.Version = initialize.ServerInfo.Version
	}

	artifactCount := 0
	if initialize.Capabilities != nil && initialize.Capabilities.Tools != nil {
		server.Tools, err = listTools(sessionCtx, session, server.ID, &artifactCount)
		if err != nil {
			return mcp.Document{}, err
		}
	}
	if initialize.Capabilities != nil && initialize.Capabilities.Prompts != nil {
		server.Prompts, err = listPrompts(sessionCtx, session, server.ID, &artifactCount)
		if err != nil {
			return mcp.Document{}, err
		}
	}
	if initialize.Capabilities != nil && initialize.Capabilities.Resources != nil {
		server.Resources, err = listResources(sessionCtx, session, server.ID, &artifactCount)
		if err != nil {
			return mcp.Document{}, err
		}
		server.ResourceTemplates, err = listResourceTemplates(sessionCtx, session, server.ID, &artifactCount)
		if err != nil {
			return mcp.Document{}, err
		}
	}

	return mcp.Document{
		SourcePath:        metadataEndpoint,
		ProtocolVersion:   initialize.ProtocolVersion,
		Servers:           []mcp.ServerConfig{server},
		Tools:             server.Tools,
		Prompts:           server.Prompts,
		Resources:         server.Resources,
		ResourceTemplates: server.ResourceTemplates,
	}, nil
}

func endpointForMetadata(endpoint *url.URL) string {
	clone := *endpoint
	query := clone.Query()
	for key, values := range query {
		for i := range values {
			values[i] = "[REDACTED_QUERY_VALUE]"
		}
		query[key] = values
	}
	clone.RawQuery = query.Encode()
	return clone.String()
}

func listTools(ctx context.Context, session *sdk.ClientSession, serverID string, count *int) ([]mcp.ToolDefinition, error) {
	var out []mcp.ToolDefinition
	err := paginate("tools/list", func(cursor string) (string, error) {
		result, err := session.ListTools(ctx, &sdk.ListToolsParams{Cursor: cursor})
		if err != nil {
			return "", err
		}
		for _, tool := range result.Tools {
			if tool == nil {
				continue
			}
			if err := incrementArtifacts(count); err != nil {
				return "", err
			}
			out = append(out, mcp.ToolDefinition{
				ServerID:     serverID,
				Name:         tool.Name,
				Title:        tool.Title,
				Description:  tool.Description,
				InputSchema:  toMap(tool.InputSchema),
				OutputSchema: toMap(tool.OutputSchema),
				Annotations:  toMap(tool.Annotations),
				Meta:         copyMap(tool.Meta),
			})
		}
		return result.NextCursor, nil
	})
	return out, wrapListError("tools/list", err)
}

func listPrompts(ctx context.Context, session *sdk.ClientSession, serverID string, count *int) ([]mcp.PromptDefinition, error) {
	var out []mcp.PromptDefinition
	err := paginate("prompts/list", func(cursor string) (string, error) {
		result, err := session.ListPrompts(ctx, &sdk.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return "", err
		}
		for _, prompt := range result.Prompts {
			if prompt == nil {
				continue
			}
			if err := incrementArtifacts(count); err != nil {
				return "", err
			}
			arguments := make([]mcp.PromptArgument, 0, len(prompt.Arguments))
			for _, argument := range prompt.Arguments {
				if argument == nil {
					continue
				}
				arguments = append(arguments, mcp.PromptArgument{
					Name: argument.Name, Title: argument.Title,
					Description: argument.Description, Required: argument.Required,
				})
			}
			out = append(out, mcp.PromptDefinition{
				ServerID: serverID, Name: prompt.Name, Title: prompt.Title,
				Description: prompt.Description, Arguments: arguments, Meta: copyMap(prompt.Meta),
			})
		}
		return result.NextCursor, nil
	})
	return out, wrapListError("prompts/list", err)
}

func listResources(ctx context.Context, session *sdk.ClientSession, serverID string, count *int) ([]mcp.ResourceDefinition, error) {
	var out []mcp.ResourceDefinition
	err := paginate("resources/list", func(cursor string) (string, error) {
		result, err := session.ListResources(ctx, &sdk.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return "", err
		}
		for _, resource := range result.Resources {
			if resource == nil {
				continue
			}
			if err := incrementArtifacts(count); err != nil {
				return "", err
			}
			out = append(out, mcp.ResourceDefinition{
				ServerID: serverID, Name: resource.Name, Title: resource.Title,
				URI: resource.URI, Description: resource.Description, MIMEType: resource.MIMEType,
				Size: resource.Size, Annotations: toMap(resource.Annotations), Meta: copyMap(resource.Meta),
			})
		}
		return result.NextCursor, nil
	})
	return out, wrapListError("resources/list", err)
}

func listResourceTemplates(ctx context.Context, session *sdk.ClientSession, serverID string, count *int) ([]mcp.ResourceTemplateDefinition, error) {
	var out []mcp.ResourceTemplateDefinition
	err := paginate("resources/templates/list", func(cursor string) (string, error) {
		result, err := session.ListResourceTemplates(ctx, &sdk.ListResourceTemplatesParams{Cursor: cursor})
		if err != nil {
			return "", err
		}
		for _, template := range result.ResourceTemplates {
			if template == nil {
				continue
			}
			if err := incrementArtifacts(count); err != nil {
				return "", err
			}
			out = append(out, mcp.ResourceTemplateDefinition{
				ServerID: serverID, Name: template.Name, Title: template.Title,
				URITemplate: template.URITemplate, Description: template.Description,
				MIMEType: template.MIMEType, Annotations: toMap(template.Annotations), Meta: copyMap(template.Meta),
			})
		}
		return result.NextCursor, nil
	})
	return out, wrapListError("resources/templates/list", err)
}

func paginate(method string, request func(string) (string, error)) error {
	cursor := ""
	seen := map[string]struct{}{}
	for page := 0; page < MaxPages; page++ {
		next, err := request(cursor)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		if _, exists := seen[next]; exists {
			return fmt.Errorf("%s returned a repeated pagination cursor", method)
		}
		seen[next] = struct{}{}
		cursor = next
	}
	return fmt.Errorf("%s exceeded the %d-page limit", method, MaxPages)
}

func incrementArtifacts(count *int) error {
	*count++
	if *count > mcp.MaxArtifacts {
		return fmt.Errorf("MCP endpoint advertised more than %d metadata artifacts", mcp.MaxArtifacts)
	}
	return nil
}

func wrapListError(method string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s failed: %w", method, err)
}

func validateEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid MCP endpoint: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("MCP inspection requires an https:// endpoint")
	}
	if parsed.Host == "" {
		return nil, errors.New("MCP endpoint host is required")
	}
	if parsed.User != nil {
		return nil, errors.New("MCP endpoint must not contain userinfo credentials")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("MCP endpoint must not contain a URL fragment")
	}
	for key := range parsed.Query() {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "key") ||
			strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "credential") {
			return nil, fmt.Errorf("MCP endpoint query parameter %q may contain a secret; use environment-backed headers", key)
		}
	}
	return parsed, nil
}

func resolveHeaders(tokenEnv string, headerEnv []string) (http.Header, error) {
	headers := make(http.Header)
	if tokenEnv != "" {
		value, ok := os.LookupEnv(tokenEnv)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("token environment variable %s is not set", tokenEnv)
		}
		headers.Set("Authorization", "Bearer "+value)
	}
	for _, item := range headerEnv {
		name, envName, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(envName) == "" {
			return nil, fmt.Errorf("invalid --header-env %q: expected Header=ENV_NAME", item)
		}
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		envName = strings.TrimSpace(envName)
		if err := validateCustomHeader(name); err != nil {
			return nil, err
		}
		if headers.Get(name) != "" {
			return nil, fmt.Errorf("header %s is configured more than once", name)
		}
		value, exists := os.LookupEnv(envName)
		if !exists || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("header environment variable %s is not set", envName)
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header environment variable %s contains a line break", envName)
		}
		headers.Set(name, value)
	}
	return headers, nil
}

func validateCustomHeader(name string) error {
	if name == "Authorization" || name == "X-Api-Key" || strings.HasPrefix(name, "X-") {
		switch strings.ToLower(name) {
		case "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
			return fmt.Errorf("header %s is not allowed", name)
		}
		return nil
	}
	return fmt.Errorf("header %s is not allowed; use Authorization, X-API-Key, or an X-* application header", name)
}

func toMap(value any) map[string]any {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func copyMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

type secureRoundTripper struct {
	base     http.RoundTripper
	origin   string
	headers  http.Header
	maxBytes int64
	budget   *responseBudget
}

func (transport *secureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme+"://"+request.URL.Host != transport.origin {
		return nil, errors.New("refusing to send MCP credentials to a different origin")
	}
	if request.Method != http.MethodPost && request.Method != http.MethodDelete {
		return nil, fmt.Errorf("MCP inspection blocked HTTP method %s", request.Method)
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	for name, values := range transport.headers {
		clone.Header.Del(name)
		for _, value := range values {
			clone.Header.Add(name, value)
		}
	}
	if clone.Method == http.MethodPost {
		body, err := inspectRequestBody(clone.Body)
		if err != nil {
			return nil, err
		}
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	}
	response, err := transport.base.RoundTrip(clone)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > transport.maxBytes {
		_ = response.Body.Close()
		return nil, fmt.Errorf("MCP response exceeds %d bytes", transport.maxBytes)
	}
	response.Body = &limitedReadCloser{
		reader: io.LimitReader(response.Body, transport.maxBytes+1),
		closer: response.Body,
		limit:  transport.maxBytes,
		budget: transport.budget,
	}
	return response, nil
}

func inspectRequestBody(body io.ReadCloser) ([]byte, error) {
	if body == nil {
		return nil, errors.New("MCP POST request body is missing")
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, MaxRequestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read MCP request body: %w", err)
	}
	if int64(len(raw)) > MaxRequestBytes {
		return nil, fmt.Errorf("MCP request exceeds %d bytes", MaxRequestBytes)
	}
	var message struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, fmt.Errorf("inspect MCP request: %w", err)
	}
	switch message.Method {
	case "initialize", "notifications/initialized", "tools/list", "prompts/list", "resources/list", "resources/templates/list":
	default:
		return nil, fmt.Errorf("MCP inspection blocked method %q", message.Method)
	}
	return raw, nil
}

type limitedReadCloser struct {
	reader io.Reader
	closer io.Closer
	limit  int64
	read   int64
	budget *responseBudget
}

func (reader *limitedReadCloser) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	previous := reader.read
	reader.read += int64(count)
	allowed := int64(count)
	if reader.read > reader.limit {
		allowed = reader.limit - previous
		if allowed < 0 {
			allowed = 0
		}
	}
	if reader.budget != nil {
		budgetAllowed := reader.budget.consume(allowed)
		if budgetAllowed < allowed {
			return int(budgetAllowed), fmt.Errorf("MCP inspection responses exceed %d total bytes", MaxSessionBytes)
		}
	}
	if reader.read > reader.limit {
		return int(allowed), fmt.Errorf("MCP response exceeds %d bytes", reader.limit)
	}
	return count, err
}

func (reader *limitedReadCloser) Close() error {
	return reader.closer.Close()
}

type responseBudget struct {
	mu        sync.Mutex
	remaining int64
}

func (budget *responseBudget) consume(requested int64) int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if requested <= 0 || budget.remaining <= 0 {
		return 0
	}
	if requested > budget.remaining {
		allowed := budget.remaining
		budget.remaining = 0
		return allowed
	}
	budget.remaining -= requested
	return requested
}
