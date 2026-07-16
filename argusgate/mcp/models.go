package mcp

import (
	"fmt"
	"reflect"
	"sort"
)

type Document struct {
	SourcePath        string
	ProtocolVersion   string
	Servers           []ServerConfig
	Tools             []ToolDefinition
	Prompts           []PromptDefinition
	Resources         []ResourceDefinition
	ResourceTemplates []ResourceTemplateDefinition
}

type ServerConfig struct {
	ID                string                       `json:"id" yaml:"id"`
	Name              string                       `json:"name,omitempty" yaml:"name,omitempty"`
	Version           string                       `json:"version,omitempty" yaml:"version,omitempty"`
	Command           string                       `json:"command,omitempty" yaml:"command,omitempty"`
	Args              []string                     `json:"args,omitempty" yaml:"args,omitempty"`
	URL               string                       `json:"url,omitempty" yaml:"url,omitempty"`
	Transport         string                       `json:"transport,omitempty" yaml:"transport,omitempty"`
	ProtocolVersion   string                       `json:"protocol_version,omitempty" yaml:"protocol_version,omitempty"`
	Instructions      string                       `json:"instructions,omitempty" yaml:"instructions,omitempty"`
	Capabilities      map[string]any               `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Env               map[string]string            `json:"env,omitempty" yaml:"env,omitempty"`
	Headers           map[string]string            `json:"headers,omitempty" yaml:"headers,omitempty"`
	Tools             []ToolDefinition             `json:"tools,omitempty" yaml:"tools,omitempty"`
	Prompts           []PromptDefinition           `json:"prompts,omitempty" yaml:"prompts,omitempty"`
	Resources         []ResourceDefinition         `json:"resources,omitempty" yaml:"resources,omitempty"`
	ResourceTemplates []ResourceTemplateDefinition `json:"resource_templates,omitempty" yaml:"resource_templates,omitempty"`
	Raw               map[string]any               `json:"-" yaml:"-"`
}

type ToolDefinition struct {
	ServerID     string         `json:"server_id" yaml:"server_id"`
	Name         string         `json:"name" yaml:"name"`
	Title        string         `json:"title,omitempty" yaml:"title,omitempty"`
	Description  string         `json:"description,omitempty" yaml:"description,omitempty"`
	InputSchema  map[string]any `json:"inputSchema,omitempty" yaml:"inputSchema,omitempty"`
	OutputSchema map[string]any `json:"outputSchema,omitempty" yaml:"outputSchema,omitempty"`
	Execution    map[string]any `json:"execution,omitempty" yaml:"execution,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Meta         map[string]any `json:"_meta,omitempty" yaml:"_meta,omitempty"`
	Raw          map[string]any `json:"-" yaml:"-"`
}

type PromptDefinition struct {
	ServerID    string           `json:"server_id" yaml:"server_id"`
	Name        string           `json:"name" yaml:"name"`
	Title       string           `json:"title,omitempty" yaml:"title,omitempty"`
	Description string           `json:"description,omitempty" yaml:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty" yaml:"arguments,omitempty"`
	Meta        map[string]any   `json:"_meta,omitempty" yaml:"_meta,omitempty"`
	Raw         map[string]any   `json:"-" yaml:"-"`
}

type PromptArgument struct {
	Name        string `json:"name" yaml:"name"`
	Title       string `json:"title,omitempty" yaml:"title,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool   `json:"required,omitempty" yaml:"required,omitempty"`
}

type ResourceDefinition struct {
	ServerID    string         `json:"server_id" yaml:"server_id"`
	Name        string         `json:"name" yaml:"name"`
	Title       string         `json:"title,omitempty" yaml:"title,omitempty"`
	URI         string         `json:"uri" yaml:"uri"`
	Description string         `json:"description,omitempty" yaml:"description,omitempty"`
	MIMEType    string         `json:"mimeType,omitempty" yaml:"mimeType,omitempty"`
	Size        int64          `json:"size,omitempty" yaml:"size,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Meta        map[string]any `json:"_meta,omitempty" yaml:"_meta,omitempty"`
	Raw         map[string]any `json:"-" yaml:"-"`
}

type ResourceTemplateDefinition struct {
	ServerID    string         `json:"server_id" yaml:"server_id"`
	Name        string         `json:"name" yaml:"name"`
	Title       string         `json:"title,omitempty" yaml:"title,omitempty"`
	URITemplate string         `json:"uriTemplate" yaml:"uriTemplate"`
	Description string         `json:"description,omitempty" yaml:"description,omitempty"`
	MIMEType    string         `json:"mimeType,omitempty" yaml:"mimeType,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Meta        map[string]any `json:"_meta,omitempty" yaml:"_meta,omitempty"`
	Raw         map[string]any `json:"-" yaml:"-"`
}

type ArtifactKind string

const (
	ArtifactTool             ArtifactKind = "tool"
	ArtifactPrompt           ArtifactKind = "prompt"
	ArtifactResource         ArtifactKind = "resource"
	ArtifactResourceTemplate ArtifactKind = "resource_template"
)

type Artifact struct {
	Kind           ArtifactKind
	ServerID       string
	Name           string
	Title          string
	Description    string
	URI            string
	URITemplate    string
	InputSchema    map[string]any
	OutputSchema   map[string]any
	Execution      map[string]any
	Arguments      []PromptArgument
	Annotations    map[string]any
	Meta           map[string]any
	Raw            map[string]any
	ToolDefinition *ToolDefinition
}

type TextBlob struct {
	Location string
	Text     string
}

func ToolTextBlobs(tool ToolDefinition) []TextBlob {
	return ArtifactTextBlobs(ArtifactFromTool(tool))
}

func ArtifactTextBlobs(artifact Artifact) []TextBlob {
	var out []TextBlob
	base := fmt.Sprintf("%ss[%s]", artifact.Kind, artifact.Name)
	addBlob(&out, base+".name", artifact.Name)
	addBlob(&out, base+".title", artifact.Title)
	addBlob(&out, base+".description", artifact.Description)
	addBlob(&out, base+".uri", artifact.URI)
	addBlob(&out, base+".uriTemplate", artifact.URITemplate)
	flattenStrings(base+".inputSchema", artifact.InputSchema, &out)
	flattenStrings(base+".outputSchema", artifact.OutputSchema, &out)
	flattenStrings(base+".execution", artifact.Execution, &out)
	flattenStrings(base+".arguments", artifact.Arguments, &out)
	flattenStrings(base+".annotations", artifact.Annotations, &out)
	flattenStrings(base+"._meta", artifact.Meta, &out)
	flattenStrings(base+".raw", artifact.Raw, &out)
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
	addBlob(&out, base+".protocolVersion", server.ProtocolVersion)
	addBlob(&out, base+".instructions", server.Instructions)
	flattenStrings(base+".args", server.Args, &out)
	flattenStrings(base+".capabilities", server.Capabilities, &out)
	flattenStrings(base+".env", server.Env, &out)
	flattenStrings(base+".headers", server.Headers, &out)
	flattenStrings(base+".raw", server.Raw, &out)
	return out
}

func DocumentArtifacts(doc Document) []Artifact {
	out := make([]Artifact, 0, len(doc.Tools)+len(doc.Prompts)+len(doc.Resources)+len(doc.ResourceTemplates))
	for _, tool := range doc.Tools {
		out = append(out, ArtifactFromTool(tool))
	}
	for _, prompt := range doc.Prompts {
		out = append(out, ArtifactFromPrompt(prompt))
	}
	for _, resource := range doc.Resources {
		out = append(out, ArtifactFromResource(resource))
	}
	for _, template := range doc.ResourceTemplates {
		out = append(out, ArtifactFromResourceTemplate(template))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ServerID != out[j].ServerID {
			return out[i].ServerID < out[j].ServerID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func ArtifactFromTool(tool ToolDefinition) Artifact {
	copy := tool
	return Artifact{
		Kind:           ArtifactTool,
		ServerID:       tool.ServerID,
		Name:           tool.Name,
		Title:          tool.Title,
		Description:    tool.Description,
		InputSchema:    tool.InputSchema,
		OutputSchema:   tool.OutputSchema,
		Execution:      tool.Execution,
		Annotations:    tool.Annotations,
		Meta:           tool.Meta,
		Raw:            tool.Raw,
		ToolDefinition: &copy,
	}
}

func ArtifactFromPrompt(prompt PromptDefinition) Artifact {
	return Artifact{
		Kind:        ArtifactPrompt,
		ServerID:    prompt.ServerID,
		Name:        prompt.Name,
		Title:       prompt.Title,
		Description: prompt.Description,
		Arguments:   prompt.Arguments,
		Meta:        prompt.Meta,
		Raw:         prompt.Raw,
	}
}

func ArtifactFromResource(resource ResourceDefinition) Artifact {
	return Artifact{
		Kind:        ArtifactResource,
		ServerID:    resource.ServerID,
		Name:        resource.Name,
		Title:       resource.Title,
		Description: resource.Description,
		URI:         resource.URI,
		Annotations: resource.Annotations,
		Meta:        resource.Meta,
		Raw:         resource.Raw,
	}
}

func ArtifactFromResourceTemplate(template ResourceTemplateDefinition) Artifact {
	return Artifact{
		Kind:        ArtifactResourceTemplate,
		ServerID:    template.ServerID,
		Name:        template.Name,
		Title:       template.Title,
		Description: template.Description,
		URITemplate: template.URITemplate,
		Annotations: template.Annotations,
		Meta:        template.Meta,
		Raw:         template.Raw,
	}
}

func addBlob(out *[]TextBlob, location string, text string) {
	if text == "" {
		return
	}
	*out = append(*out, TextBlob{Location: location, Text: text})
}

func flattenStrings(location string, value any, out *[]TextBlob) {
	flattenStringsDepth(location, value, out, 0)
}

func flattenStringsDepth(location string, value any, out *[]TextBlob, depth int) {
	if depth > MaxNestingDepth {
		addBlob(out, location, "metadata nesting exceeds safe depth")
		return
	}
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
			flattenStringsDepth(fmt.Sprintf("%s[%d]", location, i), item, out, depth+1)
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
				flattenStringsDepth(location+"."+key, item, out, depth+1)
			}
		}
	case []PromptArgument:
		for i, item := range typed {
			base := fmt.Sprintf("%s[%d]", location, i)
			addBlob(out, base+".name", item.Name)
			addBlob(out, base+".title", item.Title)
			addBlob(out, base+".description", item.Description)
		}
	case bool, int, int64, float64:
		addBlob(out, location, fmt.Sprint(typed))
	default:
		addBlob(out, location, fmt.Sprint(typed))
	}
}

func ExceedsMaxNesting(value any) bool {
	return exceedsMaxNesting(reflect.ValueOf(value), 0)
}

func exceedsMaxNesting(value reflect.Value, depth int) bool {
	if !value.IsValid() {
		return false
	}
	if depth > MaxNestingDepth {
		return true
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if exceedsMaxNesting(iterator.Value(), depth+1) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if exceedsMaxNesting(value.Index(i), depth+1) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).PkgPath == "" && exceedsMaxNesting(value.Field(i), depth+1) {
				return true
			}
		}
	}
	return false
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
