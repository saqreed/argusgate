package baseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/saqreed/argusgate/argusgate/internal/fileio"
	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
)

const MaxBaselineBytes int64 = 16 << 20

func Create(doc mcp.Document, argusGateVersion string, now time.Time) (File, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := File{
		Version:          FormatVersion,
		ArgusGateVersion: argusGateVersion,
		CreatedAt:        now.UTC().Format(time.RFC3339),
		ProtocolVersion:  redact.Text(doc.ProtocolVersion),
		Servers:          make([]ServerEntry, 0, len(doc.Servers)),
		Artifacts:        make([]ArtifactEntry, 0, len(mcp.DocumentArtifacts(doc))),
	}
	serverIdentities := make(map[string]string, len(doc.Servers))
	for _, server := range doc.Servers {
		identity := identityHash("server", server.ID)
		contractHash, err := hashCanonical(serverContract(server))
		if err != nil {
			return File{}, fmt.Errorf("hash server %q: %w", server.ID, err)
		}
		serverIdentities[server.ID] = identity
		out.Servers = append(out.Servers, ServerEntry{
			Identity:     identity,
			ID:           redact.Text(server.ID),
			ContractHash: contractHash,
		})
	}
	for _, artifact := range mcp.DocumentArtifacts(doc) {
		serverIdentity := serverIdentities[artifact.ServerID]
		if serverIdentity == "" {
			serverIdentity = identityHash("server", artifact.ServerID)
		}
		subjectIdentity := identityHash(string(artifact.Kind), serverIdentity, artifact.Name)
		contractHash, err := hashCanonical(artifactContract(artifact))
		if err != nil {
			return File{}, fmt.Errorf("hash %s %q: %w", artifact.Kind, artifact.Name, err)
		}
		out.Artifacts = append(out.Artifacts, ArtifactEntry{
			Kind:            string(artifact.Kind),
			ServerIdentity:  serverIdentity,
			SubjectIdentity: subjectIdentity,
			Name:            redact.Text(artifact.Name),
			ContractHash:    contractHash,
		})
	}
	sortFile(&out)
	return out, nil
}

func LoadFile(path string) (File, error) {
	raw, err := fileio.ReadLimitedFile(path, MaxBaselineBytes)
	if err != nil {
		return File{}, fmt.Errorf("read baseline %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var baseline File
	if err := decoder.Decode(&baseline); err != nil {
		return File{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return File{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if err := Validate(baseline); err != nil {
		return File{}, fmt.Errorf("validate baseline %s: %w", path, err)
	}
	sortFile(&baseline)
	return baseline, nil
}

func Validate(value File) error {
	if value.Version != FormatVersion {
		return fmt.Errorf("unsupported baseline version %q", value.Version)
	}
	if strings.TrimSpace(value.ArgusGateVersion) == "" {
		return fmt.Errorf("argusgate_version is required")
	}
	if _, err := time.Parse(time.RFC3339, value.CreatedAt); err != nil {
		return fmt.Errorf("created_at must use RFC3339")
	}
	if len(value.Servers)+len(value.Artifacts) > mcp.MaxArtifacts+mcp.MaxServers {
		return fmt.Errorf("baseline contains too many entries")
	}
	seenServers := make(map[string]struct{}, len(value.Servers))
	for i, server := range value.Servers {
		if strings.TrimSpace(server.ID) == "" {
			return fmt.Errorf("servers[%d].id is required", i)
		}
		if !isSHA256(server.Identity) || !isSHA256(server.ContractHash) {
			return fmt.Errorf("servers[%d] contains an invalid SHA-256 value", i)
		}
		if _, exists := seenServers[server.Identity]; exists {
			return fmt.Errorf("servers[%d].identity is duplicated", i)
		}
		seenServers[server.Identity] = struct{}{}
	}
	seenArtifacts := make(map[string]struct{}, len(value.Artifacts))
	for i, artifact := range value.Artifacts {
		if strings.TrimSpace(artifact.Name) == "" {
			return fmt.Errorf("artifacts[%d].name is required", i)
		}
		if !validKind(artifact.Kind) {
			return fmt.Errorf("artifacts[%d].kind is invalid", i)
		}
		if !isSHA256(artifact.ServerIdentity) || !isSHA256(artifact.SubjectIdentity) || !isSHA256(artifact.ContractHash) {
			return fmt.Errorf("artifacts[%d] contains an invalid SHA-256 value", i)
		}
		if _, exists := seenArtifacts[artifact.SubjectIdentity]; exists {
			return fmt.Errorf("artifacts[%d].subject_identity is duplicated", i)
		}
		seenArtifacts[artifact.SubjectIdentity] = struct{}{}
	}
	return nil
}

func JSONBytes(value File) ([]byte, error) {
	sortFile(&value)
	return json.MarshalIndent(value, "", "  ")
}

func identityHash(parts ...string) string {
	normalized := make([]string, len(parts))
	for i, part := range parts {
		normalized[i] = strings.ToLower(strings.Join(strings.Fields(redact.Text(part)), " "))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return hex.EncodeToString(sum[:])
}

func hashCanonical(value any) (string, error) {
	normalized := normalizeCanonical("", value)
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeCanonical(parent string, value any) any {
	return normalizeCanonicalDepth(parent, value, 0)
}

func normalizeCanonicalDepth(parent string, value any, depth int) any {
	if depth > mcp.MaxNestingDepth {
		return "[MAX_NESTING_DEPTH_EXCEEDED]"
	}
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return redact.Text(strings.ReplaceAll(typed, "\r\n", "\n"))
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if redact.IsSensitiveKey(key) {
				out[key] = "[REDACTED_SECRET]"
			} else {
				out[key] = normalizeCanonicalDepth(key, item, depth+1)
			}
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if redact.IsSensitiveKey(key) {
				out[key] = "[REDACTED_SECRET]"
			} else {
				out[key] = normalizeCanonicalDepth(key, item, depth+1)
			}
		}
		return out
	case []string:
		out := append([]string(nil), typed...)
		for i := range out {
			out[i] = redact.Text(strings.ReplaceAll(out[i], "\r\n", "\n"))
		}
		if isSetLike(parent) {
			sort.Strings(out)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = normalizeCanonicalDepth(parent, item, depth+1)
		}
		if isSetLike(parent) {
			sort.Slice(out, func(i, j int) bool {
				left, _ := json.Marshal(out[i])
				right, _ := json.Marshal(out[j])
				return string(left) < string(right)
			})
		}
		return out
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return redact.Text(fmt.Sprint(typed))
		}
		var generic any
		if json.Unmarshal(raw, &generic) == nil {
			return normalizeCanonicalDepth(parent, generic, depth+1)
		}
		return redact.Text(fmt.Sprint(typed))
	}
}

func isSetLike(parent string) bool {
	switch parent {
	case "required", "enum", "type":
		return true
	default:
		return false
	}
}

func serverContract(server mcp.ServerConfig) map[string]any {
	envKeys := sortedMapKeys(server.Env)
	headerKeys := sortedMapKeys(server.Headers)
	return map[string]any{
		"name":             server.Name,
		"version":          server.Version,
		"command":          server.Command,
		"args":             server.Args,
		"url":              server.URL,
		"transport":        server.Transport,
		"protocol_version": server.ProtocolVersion,
		"instructions":     server.Instructions,
		"capabilities":     server.Capabilities,
		"env_keys":         envKeys,
		"header_keys":      headerKeys,
		"raw":              server.Raw,
	}
}

func artifactContract(artifact mcp.Artifact) map[string]any {
	return map[string]any{
		"title":         artifact.Title,
		"description":   artifact.Description,
		"uri":           artifact.URI,
		"uri_template":  artifact.URITemplate,
		"input_schema":  artifact.InputSchema,
		"output_schema": artifact.OutputSchema,
		"execution":     artifact.Execution,
		"arguments":     artifact.Arguments,
		"annotations":   artifact.Annotations,
		"meta":          artifact.Meta,
		"raw":           artifact.Raw,
	}
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, redact.Text(key))
	}
	sort.Strings(keys)
	return keys
}

func sortFile(value *File) {
	sort.Slice(value.Servers, func(i, j int) bool {
		return value.Servers[i].Identity < value.Servers[j].Identity
	})
	sort.Slice(value.Artifacts, func(i, j int) bool {
		if value.Artifacts[i].Kind != value.Artifacts[j].Kind {
			return value.Artifacts[i].Kind < value.Artifacts[j].Kind
		}
		if value.Artifacts[i].ServerIdentity != value.Artifacts[j].ServerIdentity {
			return value.Artifacts[i].ServerIdentity < value.Artifacts[j].ServerIdentity
		}
		return value.Artifacts[i].SubjectIdentity < value.Artifacts[j].SubjectIdentity
	})
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not supported")
		}
		return err
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validKind(value string) bool {
	switch mcp.ArtifactKind(value) {
	case mcp.ArtifactTool, mcp.ArtifactPrompt, mcp.ArtifactResource, mcp.ArtifactResourceTemplate:
		return true
	default:
		return false
	}
}
