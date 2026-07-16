package baseline

const FormatVersion = "0.1"

type File struct {
	Version          string          `json:"version"`
	ArgusGateVersion string          `json:"argusgate_version"`
	CreatedAt        string          `json:"created_at"`
	ProtocolVersion  string          `json:"protocol_version,omitempty"`
	Servers          []ServerEntry   `json:"servers"`
	Artifacts        []ArtifactEntry `json:"artifacts"`
}

type ServerEntry struct {
	Identity     string `json:"identity"`
	ID           string `json:"id"`
	ContractHash string `json:"contract_hash"`
}

type ArtifactEntry struct {
	Kind            string `json:"kind"`
	ServerIdentity  string `json:"server_identity"`
	SubjectIdentity string `json:"subject_identity"`
	Name            string `json:"name"`
	ContractHash    string `json:"contract_hash"`
}

type Summary struct {
	Path          string `json:"path,omitempty"`
	Version       string `json:"version"`
	Added         int    `json:"added"`
	Changed       int    `json:"changed"`
	Removed       int    `json:"removed"`
	ServerChanged int    `json:"server_changed"`
}
