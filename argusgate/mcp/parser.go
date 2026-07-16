package mcp

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/fileio"
	"gopkg.in/yaml.v3"
)

const (
	MaxDocumentBytes int64 = 16 << 20
	MaxServers             = 2048
	MaxArtifacts           = 10000
	MaxNestingDepth        = 128
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
	var prompts []PromptDefinition
	var resources []ResourceDefinition
	var resourceTemplates []ResourceTemplateDefinition
	for i := range servers {
		for _, tool := range servers[i].Tools {
			tools = append(tools, tool)
		}
		prompts = append(prompts, servers[i].Prompts...)
		resources = append(resources, servers[i].Resources...)
		resourceTemplates = append(resourceTemplates, servers[i].ResourceTemplates...)
	}
	looseServerIDs := map[string]struct{}{}
	if value, ok := root["tools"]; ok {
		topLevelTools := parseTools("fixtures", value, true)
		tools = append(tools, topLevelTools...)
		collectToolServerIDs(looseServerIDs, topLevelTools)
	}
	if value, ok := root["prompts"]; ok {
		topLevelPrompts := parsePrompts("fixtures", value, true)
		prompts = append(prompts, topLevelPrompts...)
		collectPromptServerIDs(looseServerIDs, topLevelPrompts)
	}
	if value, ok := root["resources"]; ok {
		topLevelResources := parseResources("fixtures", value, true)
		resources = append(resources, topLevelResources...)
		collectResourceServerIDs(looseServerIDs, topLevelResources)
	}
	if value := firstAny(root, "resourceTemplates", "resource_templates"); value != nil {
		topLevelTemplates := parseResourceTemplates("fixtures", value, true)
		resourceTemplates = append(resourceTemplates, topLevelTemplates...)
		collectResourceTemplateServerIDs(looseServerIDs, topLevelTemplates)
	}
	if result, ok := root["result"].(map[string]any); ok {
		if value, ok := result["tools"]; ok {
			resultTools := parseTools("fixtures", value, true)
			tools = append(tools, resultTools...)
			collectToolServerIDs(looseServerIDs, resultTools)
		}
		if value, ok := result["prompts"]; ok {
			resultPrompts := parsePrompts("fixtures", value, true)
			prompts = append(prompts, resultPrompts...)
			collectPromptServerIDs(looseServerIDs, resultPrompts)
		}
		if value, ok := result["resources"]; ok {
			resultResources := parseResources("fixtures", value, true)
			resources = append(resources, resultResources...)
			collectResourceServerIDs(looseServerIDs, resultResources)
		}
		if value := firstAny(result, "resourceTemplates", "resource_templates"); value != nil {
			resultTemplates := parseResourceTemplates("fixtures", value, true)
			resourceTemplates = append(resourceTemplates, resultTemplates...)
			collectResourceTemplateServerIDs(looseServerIDs, resultTemplates)
		}
	}
	if fixtureMode && len(servers) == 0 && len(looseServerIDs) > 0 {
		servers = syntheticServers(looseServerIDs, tools, prompts, resources, resourceTemplates)
	}

	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
	sortArtifacts(tools, func(tool ToolDefinition) (string, string) { return tool.ServerID, tool.Name })
	sortArtifacts(prompts, func(prompt PromptDefinition) (string, string) { return prompt.ServerID, prompt.Name })
	sortArtifacts(resources, func(resource ResourceDefinition) (string, string) { return resource.ServerID, resource.Name })
	sortArtifacts(resourceTemplates, func(template ResourceTemplateDefinition) (string, string) { return template.ServerID, template.Name })
	if err := validateDocumentContent(path, fixtureMode, servers, tools, prompts, resources, resourceTemplates); err != nil {
		return Document{}, err
	}

	return Document{
		SourcePath:        path,
		ProtocolVersion:   firstString(root, "protocolVersion", "protocol_version"),
		Servers:           servers,
		Tools:             tools,
		Prompts:           prompts,
		Resources:         resources,
		ResourceTemplates: resourceTemplates,
	}, nil
}

func validateDocumentContent(
	path string,
	fixtureMode bool,
	servers []ServerConfig,
	tools []ToolDefinition,
	prompts []PromptDefinition,
	resources []ResourceDefinition,
	resourceTemplates []ResourceTemplateDefinition,
) error {
	if len(servers) > MaxServers {
		return fmt.Errorf("parse %s: %d servers exceed maximum of %d", path, len(servers), MaxServers)
	}
	artifactCount := len(tools) + len(prompts) + len(resources) + len(resourceTemplates)
	if artifactCount > MaxArtifacts {
		return fmt.Errorf("parse %s: %d metadata artifacts exceed maximum of %d", path, artifactCount, MaxArtifacts)
	}
	if fixtureMode && artifactCount == 0 {
		return fmt.Errorf("parse %s: no MCP metadata artifacts found", path)
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

	if err := validateNamedArtifacts(path, "tool", tools, func(tool ToolDefinition) (string, string) { return tool.ServerID, tool.Name }); err != nil {
		return err
	}
	if err := validateNamedArtifacts(path, "prompt", prompts, func(prompt PromptDefinition) (string, string) { return prompt.ServerID, prompt.Name }); err != nil {
		return err
	}
	for promptIndex, prompt := range prompts {
		seenArguments := make(map[string]struct{}, len(prompt.Arguments))
		for argumentIndex, argument := range prompt.Arguments {
			name := strings.TrimSpace(argument.Name)
			if name == "" {
				return fmt.Errorf("parse %s: prompts[%d].arguments[%d].name is required", path, promptIndex, argumentIndex)
			}
			key := strings.ToLower(name)
			if _, exists := seenArguments[key]; exists {
				return fmt.Errorf("parse %s: duplicate prompt argument %q in prompt %q", path, name, prompt.Name)
			}
			seenArguments[key] = struct{}{}
		}
	}
	if err := validateNamedArtifacts(path, "resource", resources, func(resource ResourceDefinition) (string, string) { return resource.ServerID, resource.Name }); err != nil {
		return err
	}
	if err := validateNamedArtifacts(path, "resource template", resourceTemplates, func(template ResourceTemplateDefinition) (string, string) {
		return template.ServerID, template.Name
	}); err != nil {
		return err
	}
	for i, resource := range resources {
		if strings.TrimSpace(resource.URI) == "" {
			return fmt.Errorf("parse %s: resources[%d].uri is required", path, i)
		}
	}
	for i, template := range resourceTemplates {
		if strings.TrimSpace(template.URITemplate) == "" {
			return fmt.Errorf("parse %s: resource_templates[%d].uriTemplate is required", path, i)
		}
	}
	return nil
}

func validateNamedArtifacts[T any](path, kind string, artifacts []T, identity func(T) (string, string)) error {
	seen := make(map[string]struct{}, len(artifacts))
	for i, artifact := range artifacts {
		serverID, name := identity(artifact)
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("parse %s: %ss[%d].name is required", path, strings.ReplaceAll(kind, " ", "_"), i)
		}
		key := strings.ToLower(serverID + "\x00" + name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("parse %s: duplicate %s %q for server %q", path, kind, name, serverID)
		}
		seen[key] = struct{}{}
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
	if value, ok := root["prompts"]; ok {
		if err := validatePromptsShape("prompts", value); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if value, ok := root["resources"]; ok {
		if err := validateResourcesShape("resources", value); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	for _, key := range []string{"resourceTemplates", "resource_templates"} {
		if value, ok := root[key]; ok {
			if err := validateResourceTemplatesShape(key, value); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
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
		if prompts, ok := result["prompts"]; ok {
			if err := validatePromptsShape("result.prompts", prompts); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
		}
		if resources, ok := result["resources"]; ok {
			if err := validateResourcesShape("result.resources", resources); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
		}
		for _, key := range []string{"resourceTemplates", "resource_templates"} {
			if templates, ok := result[key]; ok {
				if err := validateResourceTemplatesShape("result."+key, templates); err != nil {
					return fmt.Errorf("parse %s: %w", path, err)
				}
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

func validatePromptsShape(location string, value any) error {
	return validateMetadataShape(location, value, "prompt", validatePromptObject)
}

func validateResourcesShape(location string, value any) error {
	return validateMetadataShape(location, value, "resource", validateResourceObject)
}

func validateResourceTemplatesShape(location string, value any) error {
	return validateMetadataShape(location, value, "resource template", validateResourceTemplateObject)
}

func validateMetadataShape(
	location string,
	value any,
	kind string,
	validate func(string, map[string]any) error,
) error {
	switch typed := value.(type) {
	case []any:
		for i, item := range typed {
			raw, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s[%d]: expected %s object", location, i, kind)
			}
			if err := validate(fmt.Sprintf("%s[%d]", location, i), raw); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		keys := sortedAnyMapKeys(typed)
		for _, key := range keys {
			raw, ok := typed[key].(map[string]any)
			if !ok {
				return fmt.Errorf("%s.%s: expected %s object", location, key, kind)
			}
			if err := validate(location+"."+key, raw); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: expected %s object map or list", location, kind)
	}
}

func validateServerObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "id", "name", "server_id", "title", "version", "command", "cmd", "url", "endpoint", "base_url", "transport", "type", "protocolVersion", "protocol_version", "instructions"); err != nil {
		return err
	}
	if args, ok := raw["args"]; ok && !isStringOrScalarList(args) {
		return fmt.Errorf("%s.args: expected string or scalar list", location)
	}
	for _, key := range []string{"env", "headers", "capabilities"} {
		if value, ok := raw[key]; ok {
			if _, valid := value.(map[string]any); !valid {
				return fmt.Errorf("%s.%s: expected object", location, key)
			}
		}
	}
	if tools, ok := raw["tools"]; ok {
		if err := validateToolsShape(location+".tools", tools); err != nil {
			return err
		}
	}
	if prompts, ok := raw["prompts"]; ok {
		if err := validatePromptsShape(location+".prompts", prompts); err != nil {
			return err
		}
	}
	if resources, ok := raw["resources"]; ok {
		if err := validateResourcesShape(location+".resources", resources); err != nil {
			return err
		}
	}
	for _, key := range []string{"resourceTemplates", "resource_templates"} {
		if templates, ok := raw[key]; ok {
			if err := validateResourceTemplatesShape(location+"."+key, templates); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateToolObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "server_id", "server", "name", "id", "tool_name", "title", "description", "desc"); err != nil {
		return err
	}
	for _, key := range []string{"inputSchema", "input_schema", "schema", "outputSchema", "output_schema", "execution", "annotations", "_meta", "meta", "metadata"} {
		if value, ok := raw[key]; ok {
			if _, valid := value.(map[string]any); !valid {
				return fmt.Errorf("%s.%s: expected object", location, key)
			}
		}
	}
	return nil
}

func validatePromptObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "server_id", "server", "name", "id", "title", "description", "desc"); err != nil {
		return err
	}
	if arguments, ok := raw["arguments"]; ok {
		items, ok := arguments.([]any)
		if !ok {
			return fmt.Errorf("%s.arguments: expected list", location)
		}
		for i, item := range items {
			argument, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.arguments[%d]: expected object", location, i)
			}
			if err := requireStringFields(fmt.Sprintf("%s.arguments[%d]", location, i), argument, "name", "title", "description"); err != nil {
				return err
			}
			if required, ok := argument["required"]; ok {
				if _, valid := required.(bool); !valid {
					return fmt.Errorf("%s.arguments[%d].required: expected boolean", location, i)
				}
			}
		}
	}
	return requireObjectFields(location, raw, "_meta", "meta", "metadata")
}

func validateResourceObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "server_id", "server", "name", "id", "title", "uri", "description", "desc", "mimeType", "mime_type"); err != nil {
		return err
	}
	if size, ok := raw["size"]; ok {
		switch typed := size.(type) {
		case int:
			if typed < 0 {
				return fmt.Errorf("%s.size: expected non-negative integer", location)
			}
		case int64:
			if typed < 0 {
				return fmt.Errorf("%s.size: expected non-negative integer", location)
			}
		case uint64:
		case float64:
			if typed < 0 || math.Trunc(typed) != typed {
				return fmt.Errorf("%s.size: expected non-negative integer", location)
			}
		default:
			return fmt.Errorf("%s.size: expected non-negative integer", location)
		}
	}
	return requireObjectFields(location, raw, "annotations", "_meta", "meta", "metadata")
}

func validateResourceTemplateObject(location string, raw map[string]any) error {
	if err := requireStringFields(location, raw, "server_id", "server", "name", "id", "title", "uriTemplate", "uri_template", "description", "desc", "mimeType", "mime_type"); err != nil {
		return err
	}
	return requireObjectFields(location, raw, "annotations", "_meta", "meta", "metadata")
}

func requireObjectFields(location string, raw map[string]any, keys ...string) error {
	for _, key := range keys {
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

func syntheticServers(
	serverIDs map[string]struct{},
	tools []ToolDefinition,
	prompts []PromptDefinition,
	resources []ResourceDefinition,
	templates []ResourceTemplateDefinition,
) []ServerConfig {
	byID := make(map[string]*ServerConfig, len(serverIDs))
	for id := range serverIDs {
		server := &ServerConfig{ID: id}
		byID[id] = server
	}
	for _, tool := range tools {
		byID[tool.ServerID].Tools = append(byID[tool.ServerID].Tools, tool)
	}
	for _, prompt := range prompts {
		byID[prompt.ServerID].Prompts = append(byID[prompt.ServerID].Prompts, prompt)
	}
	for _, resource := range resources {
		byID[resource.ServerID].Resources = append(byID[resource.ServerID].Resources, resource)
	}
	for _, template := range templates {
		byID[template.ServerID].ResourceTemplates = append(byID[template.ServerID].ResourceTemplates, template)
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	servers := make([]ServerConfig, 0, len(ids))
	for _, id := range ids {
		servers = append(servers, *byID[id])
	}
	return servers
}

func collectToolServerIDs(out map[string]struct{}, values []ToolDefinition) {
	for _, value := range values {
		out[value.ServerID] = struct{}{}
	}
}

func collectPromptServerIDs(out map[string]struct{}, values []PromptDefinition) {
	for _, value := range values {
		out[value.ServerID] = struct{}{}
	}
}

func collectResourceServerIDs(out map[string]struct{}, values []ResourceDefinition) {
	for _, value := range values {
		out[value.ServerID] = struct{}{}
	}
}

func collectResourceTemplateServerIDs(out map[string]struct{}, values []ResourceTemplateDefinition) {
	for _, value := range values {
		out[value.ServerID] = struct{}{}
	}
}

func sortArtifacts[T any](values []T, identity func(T) (string, string)) {
	sort.Slice(values, func(i, j int) bool {
		leftServer, leftName := identity(values[i])
		rightServer, rightName := identity(values[j])
		if leftServer != rightServer {
			return leftServer < rightServer
		}
		return leftName < rightName
	})
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
		ID:              id,
		Name:            firstString(raw, "name", "title"),
		Version:         firstString(raw, "version"),
		Command:         firstString(raw, "command", "cmd"),
		Args:            asStringSlice(raw["args"]),
		URL:             firstString(raw, "url", "endpoint", "base_url"),
		Transport:       firstString(raw, "transport", "type"),
		ProtocolVersion: firstString(raw, "protocolVersion", "protocol_version"),
		Instructions:    firstString(raw, "instructions"),
		Capabilities:    asAnyMap(raw["capabilities"]),
		Env:             asStringMap(raw["env"]),
		Headers:         asStringMap(raw["headers"]),
		Raw: withoutKeys(
			raw,
			"id", "name", "server_id", "title", "version", "command", "cmd", "args",
			"url", "endpoint", "base_url", "transport", "type", "protocolVersion",
			"protocol_version", "instructions", "capabilities", "env", "headers", "tools",
			"prompts", "resources", "resourceTemplates", "resource_templates",
		),
	}
	server.Tools = parseTools(server.ID, raw["tools"], false)
	server.Prompts = parsePrompts(server.ID, raw["prompts"], false)
	server.Resources = parseResources(server.ID, raw["resources"], false)
	server.ResourceTemplates = parseResourceTemplates(server.ID, firstAny(raw, "resourceTemplates", "resource_templates"), false)
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
		Execution:    asAnyMap(raw["execution"]),
		Annotations:  asAnyMap(raw["annotations"]),
		Meta:         asAnyMap(firstAny(raw, "_meta", "meta", "metadata")),
		Raw:          withoutKeys(raw, "server_id", "server", "name", "id", "tool_name", "title", "description", "desc", "inputSchema", "input_schema", "schema", "outputSchema", "output_schema", "execution", "annotations", "_meta", "meta", "metadata"),
	}
}

func parsePrompts(serverID string, value any, allowServerID bool) []PromptDefinition {
	return parseNamedMetadata(
		serverID,
		value,
		allowServerID,
		func(serverID string, raw map[string]any) PromptDefinition {
			return PromptDefinition{
				ServerID:    resolvedServerID(serverID, raw, allowServerID),
				Name:        firstString(raw, "name", "id"),
				Title:       firstString(raw, "title"),
				Description: firstString(raw, "description", "desc"),
				Arguments:   parsePromptArguments(raw["arguments"]),
				Meta:        asAnyMap(firstAny(raw, "_meta", "meta", "metadata")),
				Raw:         withoutKeys(raw, "server_id", "server", "name", "id", "title", "description", "desc", "arguments", "_meta", "meta", "metadata"),
			}
		},
	)
}

func parseResources(serverID string, value any, allowServerID bool) []ResourceDefinition {
	return parseNamedMetadata(
		serverID,
		value,
		allowServerID,
		func(serverID string, raw map[string]any) ResourceDefinition {
			return ResourceDefinition{
				ServerID:    resolvedServerID(serverID, raw, allowServerID),
				Name:        firstString(raw, "name", "id"),
				Title:       firstString(raw, "title"),
				URI:         firstString(raw, "uri"),
				Description: firstString(raw, "description", "desc"),
				MIMEType:    firstString(raw, "mimeType", "mime_type"),
				Size:        asInt64(raw["size"]),
				Annotations: asAnyMap(raw["annotations"]),
				Meta:        asAnyMap(firstAny(raw, "_meta", "meta", "metadata")),
				Raw:         withoutKeys(raw, "server_id", "server", "name", "id", "title", "uri", "description", "desc", "mimeType", "mime_type", "size", "annotations", "_meta", "meta", "metadata"),
			}
		},
	)
}

func parseResourceTemplates(serverID string, value any, allowServerID bool) []ResourceTemplateDefinition {
	return parseNamedMetadata(
		serverID,
		value,
		allowServerID,
		func(serverID string, raw map[string]any) ResourceTemplateDefinition {
			return ResourceTemplateDefinition{
				ServerID:    resolvedServerID(serverID, raw, allowServerID),
				Name:        firstString(raw, "name", "id"),
				Title:       firstString(raw, "title"),
				URITemplate: firstString(raw, "uriTemplate", "uri_template"),
				Description: firstString(raw, "description", "desc"),
				MIMEType:    firstString(raw, "mimeType", "mime_type"),
				Annotations: asAnyMap(raw["annotations"]),
				Meta:        asAnyMap(firstAny(raw, "_meta", "meta", "metadata")),
				Raw:         withoutKeys(raw, "server_id", "server", "name", "id", "title", "uriTemplate", "uri_template", "description", "desc", "mimeType", "mime_type", "annotations", "_meta", "meta", "metadata"),
			}
		},
	)
}

func parseNamedMetadata[T any](
	serverID string,
	value any,
	allowServerID bool,
	parse func(string, map[string]any) T,
) []T {
	switch typed := value.(type) {
	case []any:
		out := make([]T, 0, len(typed))
		for _, item := range typed {
			raw, ok := item.(map[string]any)
			if ok {
				out = append(out, parse(serverID, raw))
			}
		}
		return out
	case map[string]any:
		keys := sortedAnyMapKeys(typed)
		out := make([]T, 0, len(keys))
		for _, key := range keys {
			raw, ok := typed[key].(map[string]any)
			if !ok {
				continue
			}
			raw = copyAnyMap(raw)
			if firstString(raw, "name", "id") == "" {
				raw["name"] = key
			}
			out = append(out, parse(serverID, raw))
		}
		return out
	default:
		return nil
	}
}

func resolvedServerID(serverID string, raw map[string]any, allowServerID bool) string {
	if allowServerID {
		if explicit := firstString(raw, "server_id", "server"); explicit != "" {
			serverID = explicit
		}
	}
	if serverID == "" {
		serverID = "fixtures"
	}
	return serverID
}

func parsePromptArguments(value any) []PromptArgument {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]PromptArgument, 0, len(items))
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if !ok {
			continue
		}
		required, _ := raw["required"].(bool)
		out = append(out, PromptArgument{
			Name:        firstString(raw, "name"),
			Title:       firstString(raw, "title"),
			Description: firstString(raw, "description"),
			Required:    required,
		})
	}
	return out
}

func asInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case uint64:
		if typed <= math.MaxInt64 {
			return int64(typed)
		}
	case float64:
		return int64(typed)
	}
	return 0
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
	return normalizeYAMLDepth(value, 0)
}

func normalizeYAMLDepth(value any, depth int) (any, error) {
	if depth > MaxNestingDepth {
		return nil, fmt.Errorf("metadata nesting exceeds maximum depth of %d", MaxNestingDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized, err := normalizeYAMLDepth(item, depth+1)
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
			normalized, err := normalizeYAMLDepth(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[stringKey] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			normalized, err := normalizeYAMLDepth(item, depth+1)
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
