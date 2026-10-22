package maintenance

import "context"

type OperationRequest struct {
	Action     string `json:"action"`
	UploadID   string `json:"upload_id,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	BackupName string `json:"backup_name,omitempty"`
}

type OperationProgress struct {
	Step    int
	Total   int
	Message string
}

type UpdateReview struct {
	CurrentVersion    string `json:"current_version"`
	CurrentBuildID    string `json:"current_build_id"`
	CandidateVersion  string `json:"candidate_version"`
	CandidateBuildID  string `json:"candidate_build_id"`
	TargetOS          string `json:"target_os"`
	Architecture      string `json:"architecture"`
	DatabaseSchemaMin int    `json:"database_schema_minimum"`
	DatabaseSchemaMax int    `json:"database_schema_maximum"`
}

type ReleaseState struct {
	Current  ReleaseVersion `json:"current"`
	Previous ReleaseVersion `json:"previous"`
}

type ReleaseVersion struct {
	Version string `json:"version,omitempty"`
	BuildID string `json:"build_id,omitempty"`
}

// Operations are fixed callbacks implemented by the packaged maintenance
// binary. HTTP callers can select only these named operations and bounded
// identifiers; they cannot pass commands, paths, or arbitrary arguments.
type Operations struct {
	Run            func(context.Context, OperationRequest, func(OperationProgress)) (string, error)
	ValidateUpdate func(context.Context, string, string) (UpdateReview, error)
	ReleaseState   func(context.Context) (ReleaseState, error)
}
