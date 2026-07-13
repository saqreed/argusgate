package mcp

import (
	"fmt"
	"sort"
)

type Document struct {
	SourcePath string
	Servers    []ServerConfig
	Tools      []ToolDefinition
}

type ServerConfig struct {
	ID        string            `json:"id" yaml:"id"`
	Name      string            `json:"name,omitempty" yaml:"name,omitempty"`
	Command   string            `json:"command,omitempty" yaml:"command,omitempty"`
	Args      []string          `json:"args,omitempty" yaml:"args,omitempty"`
	URL       string            `json:"url,omitempty" yaml:"url,omitempty"`
	Transport string            `json:"transport,omitempty" yaml:"transport,omitempty"`
	Env       map[string]string `json:"env,omitempty" yaml:"env,omitempty"`
	Headers   map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Tools     []ToolDefinition  `json:"tools,omitempty" yaml:"tools,omitempty"`
	Raw       map[string]any    `json:"-" yaml:"-"`
}

type ToolDefinition struct {
	ServerID     string         `json:"server_id" yaml:"server_id"`
	Name         string         `json:"name" yaml:"name"`
	Title        string         `json:"title,omitempty" yaml:"title,omitempty"`
	Description  string         `json:"description,omitempty" yaml:"description,omitempty"`
	InputSchema  map[string]any `json:"inputSchema,omitempty" yaml:"inputSchema,omitempty"`
	OutputSchema map[string]any `json:"outputSchema,omitempty" yaml:"outputSchema,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Meta         map[string]any `json:"_meta,omitempty" yaml:"_meta,omitempty"`
	Raw          map[string]any `json:"-" yaml:"-"`
}

type TextBlob struct {
	Location string
	Text     string
}

func ToolTextBlobs(tool ToolDefinition) []TextBlob {
	var out []TextBlob
	base := fmt.Sprintf("tools[%s]", tool.Name)
	addBlob(&out, base+".name", tool.Name)
	addBlob(&out, base+".title", tool.Title)
	addBlob(&out, base+".description", tool.Description)
	flattenStrings(base+".inputSchema", tool.InputSchema, &out)
	flattenStrings(base+".outputSchema", tool.OutputSchema, &out)
	flattenStrings(base+".annotations", tool.Annotations, &out)
	flattenStrings(base+"._meta", tool.Meta, &out)
	flattenStrings(base+".raw", tool.Raw, &out)
	return out
}

func ServerTextBlobs(server ServerConfig) []TextBlob {
	var out []TextBlob
	base := fmt.Sprintf("servers[%s]", server.ID)
	addBlob(&out, base+".id", server.ID)
	addBlob(&out, base+".name", server.Name)
	addBlob(&out, base+".command", server.Command)
	addBlob(&out, base+".url", server.URL)
	addBlob(&out, base+".transport", server.Transport)
	flattenStrings(base+".args", server.Args, &out)
	flattenStrings(base+".env", server.Env, &out)
	flattenStrings(base+".headers", server.Headers, &out)
	flattenStrings(base+".raw", server.Raw, &out)
	return out
}

func addBlob(out *[]TextBlob, location string, text string) {
	if text == "" {
		return
	}
	*out = append(*out, TextBlob{Location: location, Text: text})
}

func flattenStrings(location string, value any, out *[]TextBlob) {
	switch typed := value.(type) {
	case nil:
		return
	case string:
		addBlob(out, location, typed)
	case []string:
		for i, item := range typed {
			addBlob(out, fmt.Sprintf("%s[%d]", location, i), item)
		}
	case []any:
		for i, item := range typed {
			flattenStrings(fmt.Sprintf("%s[%d]", location, i), item, out)
		}
	case map[string]string:
		for _, key := range sortedStringMapKeys(typed) {
			addBlob(out, location+"."+key, fmt.Sprintf("%s=%q", key, typed[key]))
		}
	case map[string]any:
		for _, key := range sortedAnyMapKeys(typed) {
			item := typed[key]
			switch scalar := item.(type) {
			case string:
				addBlob(out, location+"."+key, fmt.Sprintf("%s=%q", key, scalar))
			case bool, int, int64, uint64, float64:
				addBlob(out, location+"."+key, fmt.Sprintf("%s=%v", key, scalar))
			default:
				addBlob(out, location+"."+key+".key", key)
				flattenStrings(location+"."+key, item, out)
			}
		}
	case bool, int, int64, float64:
		addBlob(out, location, fmt.Sprint(typed))
	default:
		addBlob(out, location, fmt.Sprint(typed))
	}
}

func sortedStringMapKeys(value map[string]string) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedAnyMapKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
