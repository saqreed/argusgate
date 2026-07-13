package mcp

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/fileio"
	"gopkg.in/yaml.v3"
)

const (
	MaxDocumentBytes int64 = 16 << 20
	MaxServers             = 2048
	MaxTools               = 10000
)

func LoadFixtures(path string) (Document, error) {
	return loadDocument(path, true)
}

func LoadConfig(path string) (Document, error) {
	return loadDocument(path, false)
}

func loadDocument(path string, fixtureMode bool) (Document, error) {
	root, err := readRoot(path)
	if err != nil {
		return Document{}, err
	}
	if err := validateDocumentShapes(path, root); err != nil {
		return Document{}, err
	}

	var servers []ServerConfig
	if value, ok := root["servers"]; ok {
		servers = append(servers, parseServers(value)...)
	}
	if value, ok := root["mcpServers"]; ok {
		servers = append(servers, parseNamedServerMap(value)...)
	}
	if value, ok := root["mcp_servers"]; ok {
		servers = append(servers, parseNamedServerMap(value)...)
	}

	var tools []ToolDefinition
	for i := range servers {
		for _, tool := range servers[i].Tools {
			tools = append(tools, tool)
		}
	}
	var looseTools []ToolDefinition
	if value, ok := root["tools"]; ok {
		topLevelTools := parseTools("fixtures", value, true)
		tools = append(tools, topLevelTools...)
		looseTools = append(looseTools, topLevelTools...)
	}
	if result, ok := root["result"].(map[string]any); ok {
		if value, ok := result["tools"]; ok {
			resultTools := parseTools("fixtures", value, true)
			tools = append(tools, resultTools...)
			looseTools = append(looseTools, resultTools...)
		}
	}
	if fixtureMode && len(servers) == 0 && len(looseTools) > 0 {
		servers = append(servers, syntheticServersForTools(looseTools, looseTools)...)
	}

	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].ServerID == tools[j].ServerID {
			return tools[i].Name < tools[j].Name
		}
		return tools[i].ServerID < tools[j].ServerID
	})
	if err := validateDocumentContent(path, fixtureMode, servers, tools); err != nil {
		return Document{}, err
	}

	return Document{SourcePath: path, Servers: servers, Tools: tools}, nil
}

func validateDocumentContent(path string, fixtureMode bool, servers []ServerConfig, tools []ToolDefinition) error {
	if len(servers) > MaxServers {
		return fmt.Errorf("parse %s: %d servers exceed maximum of %d", path, len(servers), MaxServers)
	}
	if len(tools) > MaxTools {
		return fmt.Errorf("parse %s: %d tools exceed maximum of %d", path, len(tools), MaxTools)
	}
	if fixtureMode && len(tools) == 0 {
		return fmt.Errorf("parse %s: no MCP tools found", path)
	}
	if !fixtureMode && len(servers) == 0 {
		return fmt.Errorf("parse %s: no MCP servers found", path)
	}

	serverIDs := make(map[string]struct{}, len(servers))
	for i, server := range servers {
		id := strings.TrimSpace(server.ID)
		if id == "" {
			return fmt.Errorf("parse %s: servers[%d].id is required", path, i)
		}
		key := strings.ToLower(id)
		if _, exists := serverIDs[key]; exists {
			return fmt.Errorf("parse %s: duplicate server id %q", path, server.ID)
		}
		serverIDs[key] = struct{}{}
	}

	toolNames := make(map[string]struct{}, len(tools))
	for i, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			return fmt.Errorf("parse %s: tools[%d].name is required", path, i)
		}
		key := strings.ToLower(tool.ServerID + "\x00" + name)
		if _, exists := toolNames[key]; exists {
			return fmt.Errorf("parse %s: duplicate tool %q for server %q", path, tool.Name, tool.ServerID)
		}
		toolNames[key] = struct{}{}
	}
	return nil
}

func validateDocumentShapes(path string, root map[string]any) error {
	if value, ok := root["servers"]; ok {
		if err := validateServersShape("servers", value); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if value, ok := root["mcpServers"]; ok {
		if err := validateNamedServerMapShape("mcpServers", value); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if value, ok := root["mcp_servers"]; ok {
		if err := validateNamedServerMapShape("mcp_servers", value); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if value, ok := root["tools"]; ok {
		if err := validateToolsShape("tools", value); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if value, ok := root["result"]; ok {
		result, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("parse %s: result: expected object", path)
		}
		if tools, ok := result["tools"]; ok {
			if err := validateToolsShape("result.tools", tools); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
		}
	}
	return nil
}

func validateServersShape(location string, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		return validateNamedServerMapShape(location, typed)
	case []any:
		for i, item := range typed {
			raw, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s[%d]: expected server object", location, i)
			}
			if err := validateServerObject(fmt.Sprintf("%s[%d]", location, i), raw); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: expected server object or list", location)
	}
}

func validateNamedServerMapShape(location string, value any) error {
	rawMap, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: expected server object map", location)
	}
	keys := make([]string, 0, len(rawMap))
	for key := range rawMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, id := range keys {
		item := rawMap[id]
		raw, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.%s: expected server object", location, id)
		}
		if err := validateServerObject(fmt.Sprintf("%s.%s", location, id), raw); err != nil {
			return err
		}
	}
	return nil
}

func validateToolsShape(location string, value any) error {
	switch typed := value.(type) {
	case []any:
		for i, item := range typed {
			raw, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s[%d]: expected tool object", location, i)
			}
			if err := validateToolObject(fmt.Sprintf("%s[%d]", location, i), raw); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if raw, ok := typed[key].(map[string]any); ok {
				if err := validateToolObject(location+"."+key, raw); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: expected tool object map or list", location)
	}
}

func validateServerObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "id", "name", "server_id", "title", "command", "cmd", "url", "endpoint", "base_url", "transport", "type"); err != nil {
		return err
	}
	if args, ok := raw["args"]; ok && !isStringOrScalarList(args) {
		return fmt.Errorf("%s.args: expected string or scalar list", location)
	}
	for _, key := range []string{"env", "headers"} {
		if value, ok := raw[key]; ok {
			if _, valid := value.(map[string]any); !valid {
				return fmt.Errorf("%s.%s: expected object", location, key)
			}
		}
	}
	if tools, ok := raw["tools"]; ok {
		return validateToolsShape(location+".tools", tools)
	}
	return nil
}

func validateToolObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "server_id", "server", "name", "id", "tool_name", "title", "description", "desc"); err != nil {
		return err
	}
	for _, key := range []string{"inputSchema", "input_schema", "schema", "outputSchema", "output_schema", "annotations", "_meta", "meta", "metadata"} {
		if value, ok := raw[key]; ok {
			if _, valid := value.(map[string]any); !valid {
				return fmt.Errorf("%s.%s: expected object", location, key)
			}
		}
	}
	return nil
}

func requireStringFields(location string, raw map[string]any, keys ...string) error {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if _, valid := value.(string); !valid {
				return fmt.Errorf("%s.%s: expected string", location, key)
			}
		}
	}
	return nil
}

func isStringOrScalarList(value any) bool {
	if _, ok := value.(string); ok {
		return true
	}
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		switch item.(type) {
		case string, bool, int, int64, uint64, float64, nil:
		default:
			return false
		}
	}
	return true
}

func syntheticServersForTools(tools []ToolDefinition, rawTools any) []ServerConfig {
	byServer := make(map[string][]ToolDefinition)
	for _, tool := range tools {
		serverID := tool.ServerID
		if serverID == "" {
			serverID = "fixtures"
		}
		byServer[serverID] = append(byServer[serverID], tool)
	}

	ids := make([]string, 0, len(byServer))
	for id := range byServer {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	servers := make([]ServerConfig, 0, len(ids))
	for _, id := range ids {
		servers = append(servers, ServerConfig{
			ID:    id,
			Tools: byServer[id],
			Raw:   map[string]any{"tools": rawTools},
		})
	}
	return servers
}

func readRoot(path string) (map[string]any, error) {
	raw, err := fileio.ReadLimitedFile(path, MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var decoded any
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse %s: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	normalized, err := normalizeYAML(decoded)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	root, ok := normalized.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parse %s: expected top-level object", path)
	}
	return root, nil
}

func parseServers(value any) []ServerConfig {
	switch typed := value.(type) {
	case map[string]any:
		return parseNamedServerMap(typed)
	case []any:
		var servers []ServerConfig
		for _, item := range typed {
			raw, ok := item.(map[string]any)
			if !ok {
				continue
			}
			id := firstString(raw, "id", "name", "server_id")
			servers = append(servers, parseServer(id, raw))
		}
		return servers
	default:
		return nil
	}
}

func parseNamedServerMap(value any) []ServerConfig {
	rawMap, ok := value.(map[string]any)
	if !ok {
		return nil
	}

	keys := make([]string, 0, len(rawMap))
	for key := range rawMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	servers := make([]ServerConfig, 0, len(keys))
	for _, id := range keys {
		raw, _ := rawMap[id].(map[string]any)
		servers = append(servers, parseServer(id, raw))
	}
	return servers
}

func parseServer(id string, raw map[string]any) ServerConfig {
	if raw == nil {
		raw = map[string]any{}
	}
	if id == "" {
		id = firstString(raw, "id", "name", "server_id")
	}
	if id == "" {
		id = "unknown-server"
	}

	server := ServerConfig{
		ID:        id,
		Name:      firstString(raw, "name", "title"),
		Command:   firstString(raw, "command", "cmd"),
		Args:      asStringSlice(raw["args"]),
		URL:       firstString(raw, "url", "endpoint", "base_url"),
		Transport: firstString(raw, "transport", "type"),
		Env:       asStringMap(raw["env"]),
		Headers:   asStringMap(raw["headers"]),
		Raw:       withoutKeys(raw, "id", "name", "server_id", "title", "command", "cmd", "args", "url", "endpoint", "base_url", "transport", "type", "env", "headers", "tools"),
	}
	server.Tools = parseTools(server.ID, raw["tools"], false)
	return server
}

func parseTools(serverID string, value any, allowToolServerID bool) []ToolDefinition {
	switch typed := value.(type) {
	case []any:
		return parseToolList(serverID, typed, allowToolServerID)
	case map[string]any:
		return parseToolMap(serverID, typed, allowToolServerID)
	default:
		return nil
	}
}

func parseToolList(serverID string, items []any, allowToolServerID bool) []ToolDefinition {
	tools := make([]ToolDefinition, 0, len(items))
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tools = append(tools, parseTool(serverID, raw, allowToolServerID))
	}
	return tools
}

func parseToolMap(serverID string, items map[string]any, allowToolServerID bool) []ToolDefinition {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	tools := make([]ToolDefinition, 0, len(keys))
	for _, key := range keys {
		raw, ok := items[key].(map[string]any)
		if !ok {
			raw = map[string]any{"description": fmt.Sprint(items[key])}
		} else {
			raw = copyAnyMap(raw)
		}
		if firstString(raw, "name", "id", "tool_name") == "" {
			raw["name"] = key
		}
		tools = append(tools, parseTool(serverID, raw, allowToolServerID))
	}
	return tools
}

func parseTool(serverID string, raw map[string]any, allowToolServerID bool) ToolDefinition {
	if allowToolServerID {
		if explicitServerID := firstString(raw, "server_id", "server"); explicitServerID != "" {
			serverID = explicitServerID
		}
	}
	if serverID == "" {
		serverID = firstString(raw, "server_id", "server")
	}
	if serverID == "" {
		serverID = "fixtures"
	}

	return ToolDefinition{
		ServerID:     serverID,
		Name:         firstString(raw, "name", "id", "tool_name"),
		Title:        firstString(raw, "title"),
		Description:  firstString(raw, "description", "desc"),
		InputSchema:  asAnyMap(firstAny(raw, "inputSchema", "input_schema", "schema")),
		OutputSchema: asAnyMap(firstAny(raw, "outputSchema", "output_schema")),
		Annotations:  asAnyMap(raw["annotations"]),
		Meta:         asAnyMap(firstAny(raw, "_meta", "meta", "metadata")),
		Raw:          withoutKeys(raw, "server_id", "server", "name", "id", "tool_name", "title", "description", "desc", "inputSchema", "input_schema", "schema", "outputSchema", "output_schema", "annotations", "_meta", "meta", "metadata"),
	}
}

func copyAnyMap(raw map[string]any) map[string]any {
	out := make(map[string]any, len(raw))
	for key, value := range raw {
		out[key] = value
	}
	return out
}

func withoutKeys(raw map[string]any, keys ...string) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	deny := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		deny[key] = struct{}{}
	}
	out := make(map[string]any)
	for key, value := range raw {
		if _, denied := deny[key]; denied {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if text, ok := value.(string); ok {
				return text
			}
		}
	}
	return ""
}

func firstAny(raw map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			return value
		}
	}
	return nil
}

func asStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func asStringMap(value any) map[string]string {
	raw, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, item := range raw {
		out[key] = fmt.Sprint(item)
	}
	return out
}

func asAnyMap(value any) map[string]any {
	raw, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return raw
}

func normalizeYAML(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			stringKey, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("mapping keys must be strings, got %T", key)
			}
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			out[stringKey] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	default:
		return value, nil
	}
}
