/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package mcp

import (
	"context"
	"fmt"
	"time"

	"net/url"

	"github.com/pkg/errors"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/pelican_url"
)

// unlockHint is the out-of-band remedy for a locked wallet. The password is
// deliberately not accepted over MCP: it would otherwise pass through the
// assistant's conversation transcript or an MCP client config file on disk.
const unlockHint = "The Pelican client agent's credential wallet is locked, so only public data is reachable. " +
	"To unlock it, the user must run `pelican client-agent warm <url>` (add --write for uploads) " +
	"in a terminal; that acquires the credential interactively and unlocks the wallet. " +
	"Do not ask the user for their wallet password -- this server cannot accept it."

// unlockHintFor tailors the remedy to an operation, since which URLs need
// warming -- and with which scopes -- differs between them. A third-party copy
// is the awkward case: it needs a read credential for the source and a write
// credential for the destination, so warming just one side is not enough.
func unlockHintFor(operation string) string {
	switch operation {
	case "put":
		return unlockHint + " This was an upload, so warm the destination with --write."
	case "copy":
		return unlockHint + " A copy needs both sides: warm the source for reading, " +
			"and warm the destination with --write."
	default:
		return unlockHint
	}
}

// maxJobListLimit bounds how many jobs pelican_job_list will return.
const maxJobListLimit = 100

// registerTools installs every Pelican tool on the protocol server.
func (s *Server) registerTools(srv *mcpsdk.Server) {
	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "pelican_stat",
		Title: "Stat a Pelican object",
		Description: "Get metadata (size, modification time, checksums) for an object or collection in a " +
			"Pelican data federation. Accepts pelican:// and osdf:// URLs.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleStat)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "pelican_list",
		Title:       "List a Pelican collection",
		Description: "List the contents of a collection (directory) in a Pelican data federation.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleList)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "pelican_get",
		Title: "Download from Pelican",
		Description: "Download an object or collection from a Pelican data federation to a local path. " +
			"IMPORTANT: ask the user where to save the data; do not guess a destination. " +
			"The transfer runs asynchronously in the Pelican client agent. If it does not finish quickly " +
			"this returns a job_id -- poll it with pelican_job_status rather than re-submitting.",
		Annotations: &mcpsdk.ToolAnnotations{IdempotentHint: true},
	}, s.handleGet)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "pelican_put",
		Title: "Upload to Pelican",
		Description: "Upload a local file or directory to a Pelican data federation. " +
			"The transfer runs asynchronously in the Pelican client agent; uploads are often large, so " +
			"expect a job_id back and poll it with pelican_job_status rather than re-submitting. " +
			"Uploads require a write credential: if the wallet is locked the user must run " +
			"`pelican client-agent warm <url> --write` in a terminal first.",
	}, s.handlePut)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "pelican_copy",
		Title: "Copy between Pelican locations",
		Description: "Copy an object or collection from one place in a Pelican data federation to another " +
			"without routing the bytes through this machine (a third-party copy). Both source and " +
			"destination must be pelican:// or osdf:// URLs; use pelican_get or pelican_put to move data " +
			"to or from a local path. Runs asynchronously in the Pelican client agent, so expect a job_id " +
			"back and poll it with pelican_job_status. This needs a read credential for the source and a " +
			"write credential for the destination.",
	}, s.handleCopy)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "pelican_job_status",
		Title: "Check a Pelican transfer job",
		Description: "Report the progress of an asynchronous transfer job started by pelican_get or " +
			"pelican_put. Poll this rather than resubmitting a transfer that has not finished.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleJobStatus)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "pelican_job_list",
		Title:       "List Pelican transfer jobs",
		Description: "List recent transfer jobs known to the Pelican client agent, most recent first.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleJobList)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "pelican_job_cancel",
		Title:       "Cancel a Pelican transfer job",
		Description: "Cancel an in-flight transfer job. Transfers that already completed are left alone.",
	}, s.handleJobCancel)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "pelican_wallet_status",
		Title: "Check Pelican credential status",
		Description: "Report whether the Pelican client agent's credential wallet is unlocked. " +
			"Public data needs no credential; protected namespaces do. Call this to explain an " +
			"authorization failure, or before an upload.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleWalletStatus)
}

// --- stat ---

type StatIn struct {
	URL string `json:"url" jsonschema:"the pelican:// or osdf:// URL to describe"`
}

type StatOut struct {
	Name         string            `json:"name"`
	Size         int64             `json:"size" jsonschema:"size in bytes"`
	IsCollection bool              `json:"is_collection" jsonschema:"true if this is a collection (directory)"`
	ModTime      time.Time         `json:"mod_time"`
	Checksums    map[string]string `json:"checksums,omitempty"`
}

func (s *Server) handleStat(ctx context.Context, _ *mcpsdk.CallToolRequest, in StatIn) (*mcpsdk.CallToolResult, StatOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, StatOut{}, err
	}
	res, err := agent.Stat(ctx, in.URL, client_agent.TransferOptions{})
	if err != nil {
		return nil, StatOut{}, s.explain(ctx, agent, "", errors.Wrapf(err, "failed to stat %s", in.URL))
	}
	return nil, StatOut{
		Name:         res.Name,
		Size:         res.Size,
		IsCollection: res.IsCollection,
		ModTime:      res.ModTime,
		Checksums:    res.Checksums,
	}, nil
}

// --- list ---

type ListIn struct {
	URL string `json:"url" jsonschema:"the pelican:// or osdf:// URL of the collection to list"`
}

type ListEntry struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	IsCollection bool      `json:"is_collection"`
	ModTime      time.Time `json:"mod_time"`
}

type ListOut struct {
	URL   string      `json:"url"`
	Count int         `json:"count"`
	Items []ListEntry `json:"items"`
}

func (s *Server) handleList(ctx context.Context, _ *mcpsdk.CallToolRequest, in ListIn) (*mcpsdk.CallToolResult, ListOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, ListOut{}, err
	}
	res, err := agent.List(ctx, in.URL, client_agent.TransferOptions{})
	if err != nil {
		return nil, ListOut{}, s.explain(ctx, agent, "", errors.Wrapf(err, "failed to list %s", in.URL))
	}
	out := ListOut{URL: in.URL, Count: len(res.Items), Items: make([]ListEntry, 0, len(res.Items))}
	for _, it := range res.Items {
		out.Items = append(out.Items, ListEntry{
			Name:         it.Name,
			Size:         it.Size,
			IsCollection: it.IsCollection,
			ModTime:      it.ModTime,
		})
	}
	return nil, out, nil
}

// --- transfers ---

type GetIn struct {
	Source      string `json:"source" jsonschema:"the pelican:// or osdf:// URL to download"`
	Destination string `json:"destination" jsonschema:"local path to write to; ask the user for this rather than guessing"`
	Recursive   bool   `json:"recursive,omitempty" jsonschema:"download a whole collection rather than a single object"`
}

type PutIn struct {
	Source      string `json:"source" jsonschema:"local path to upload"`
	Destination string `json:"destination" jsonschema:"the pelican:// or osdf:// URL to upload to"`
	Recursive   bool   `json:"recursive,omitempty" jsonschema:"upload a whole directory rather than a single file"`
}

func (s *Server) handleGet(ctx context.Context, _ *mcpsdk.CallToolRequest, in GetIn) (*mcpsdk.CallToolResult, JobOut, error) {
	return s.submit(ctx, client_agent.TransferRequest{
		Operation:   "get",
		Source:      in.Source,
		Destination: in.Destination,
		Recursive:   in.Recursive,
	})
}

func (s *Server) handlePut(ctx context.Context, _ *mcpsdk.CallToolRequest, in PutIn) (*mcpsdk.CallToolResult, JobOut, error) {
	return s.submit(ctx, client_agent.TransferRequest{
		Operation:   "put",
		Source:      in.Source,
		Destination: in.Destination,
		Recursive:   in.Recursive,
	})
}

type CopyIn struct {
	Source      string `json:"source" jsonschema:"the pelican:// or osdf:// URL to copy from"`
	Destination string `json:"destination" jsonschema:"the pelican:// or osdf:// URL to copy to"`
	Recursive   bool   `json:"recursive,omitempty" jsonschema:"copy a whole collection rather than a single object"`
}

func (s *Server) handleCopy(ctx context.Context, _ *mcpsdk.CallToolRequest, in CopyIn) (*mcpsdk.CallToolResult, JobOut, error) {
	// The underlying client silently degrades a half-local copy into a get or
	// a put. Reject it here instead: a model that reached for pelican_copy
	// with a local path has picked the wrong tool, and saying so plainly beats
	// quietly doing something other than a third-party copy.
	if err := requireRemote("source", in.Source); err != nil {
		return nil, JobOut{}, err
	}
	if err := requireRemote("destination", in.Destination); err != nil {
		return nil, JobOut{}, err
	}
	return s.submit(ctx, client_agent.TransferRequest{
		Operation:   "copy",
		Source:      in.Source,
		Destination: in.Destination,
		Recursive:   in.Recursive,
	})
}

// requireRemote rejects anything that is not a federation URL.
func requireRemote(field, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.Wrapf(err, "could not parse %s %q", field, raw)
	}
	if !pelican_url.IsPelicanScheme(parsed.Scheme) {
		return errors.Errorf(
			"pelican_copy needs a federation URL for the %s, but got %q; "+
				"use pelican_get to download to a local path, or pelican_put to upload from one",
			field, raw)
	}
	return nil
}

// submit queues a transfer with the agent and waits briefly for it to settle,
// so that short transfers complete within a single tool call while long ones
// return a job ID promptly.
func (s *Server) submit(ctx context.Context, req client_agent.TransferRequest) (*mcpsdk.CallToolResult, JobOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, JobOut{}, err
	}

	jobID, err := agent.CreateJob(ctx, []client_agent.TransferRequest{req}, client_agent.TransferOptions{})
	if err != nil {
		return nil, JobOut{}, s.explain(ctx, agent, req.Operation, errors.Wrap(err, "failed to submit the transfer"))
	}

	status, err := s.settle(ctx, agent, jobID)
	if err != nil {
		// The job exists even though we lost track of it; say so rather than
		// leaving the assistant to assume nothing was submitted.
		return nil, JobOut{
			JobID:    jobID,
			Status:   client_agent.StatusPending,
			NextStep: fmt.Sprintf("Submitted, but checking on it failed (%v). Poll pelican_job_status with job_id %s.", err, jobID),
		}, nil
	}
	return nil, s.describe(ctx, agent, status), nil
}

// settle polls a freshly submitted job until it reaches a terminal state or
// the settle window elapses.
func (s *Server) settle(ctx context.Context, agent agentAPI, jobID string) (*client_agent.JobStatus, error) {
	deadline := time.Now().Add(s.settleTimeout())
	ticker := time.NewTicker(settlePollInterval)
	defer ticker.Stop()

	for {
		status, err := agent.GetJobStatus(ctx, jobID)
		if err != nil {
			return nil, err
		}
		if isTerminal(status.Status) || time.Now().After(deadline) {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, nil
		case <-ticker.C:
		}
	}
}

func isTerminal(status string) bool {
	switch status {
	case client_agent.StatusCompleted, client_agent.StatusFailed, client_agent.StatusCancelled:
		return true
	}
	return false
}

// --- job reporting ---

type JobStatusIn struct {
	JobID string `json:"job_id" jsonschema:"the job ID returned by pelican_get or pelican_put"`
}

type TransferOut struct {
	Operation        string `json:"operation"`
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	Status           string `json:"status"`
	BytesTransferred int64  `json:"bytes_transferred"`
	TotalBytes       int64  `json:"total_bytes"`
	Error            string `json:"error,omitempty"`
}

type JobOut struct {
	JobID              string        `json:"job_id"`
	Status             string        `json:"status" jsonschema:"pending, running, completed, failed or cancelled"`
	Done               bool          `json:"done" jsonschema:"true once the job has reached a terminal state"`
	BytesTransferred   int64         `json:"bytes_transferred"`
	TotalBytes         int64         `json:"total_bytes"`
	TransfersCompleted int           `json:"transfers_completed"`
	TransfersFailed    int           `json:"transfers_failed"`
	TransfersTotal     int           `json:"transfers_total"`
	Transfers          []TransferOut `json:"transfers,omitempty"`
	Error              string        `json:"error,omitempty"`
	NextStep           string        `json:"next_step,omitempty" jsonschema:"what the assistant should do next"`
}

func (s *Server) handleJobStatus(ctx context.Context, _ *mcpsdk.CallToolRequest, in JobStatusIn) (*mcpsdk.CallToolResult, JobOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, JobOut{}, err
	}
	status, err := agent.GetJobStatus(ctx, in.JobID)
	if err != nil {
		return nil, JobOut{}, errors.Wrapf(err, "failed to look up job %s", in.JobID)
	}
	return nil, s.describe(ctx, agent, status), nil
}

// describe converts an agent job status into the tool's output shape and adds
// guidance on what to do next.
func (s *Server) describe(ctx context.Context, agent agentAPI, status *client_agent.JobStatus) JobOut {
	out := JobOut{
		JobID:  status.JobID,
		Status: status.Status,
		Done:   isTerminal(status.Status),
		Error:  status.Error,
	}
	if p := status.Progress; p != nil {
		out.BytesTransferred = p.BytesTransferred
		out.TotalBytes = p.TotalBytes
		out.TransfersCompleted = p.TransfersCompleted
		out.TransfersFailed = p.TransfersFailed
		out.TransfersTotal = p.TransfersTotal
	}
	for _, t := range status.Transfers {
		out.Transfers = append(out.Transfers, TransferOut{
			Operation:        t.Operation,
			Source:           t.Source,
			Destination:      t.Destination,
			Status:           t.Status,
			BytesTransferred: t.BytesTransferred,
			TotalBytes:       t.TotalBytes,
			Error:            t.Error,
		})
	}

	switch {
	case status.Status == client_agent.StatusFailed:
		out.NextStep = "The transfer failed; report the error to the user."
		if hint := s.walletHint(ctx, agent, jobOperation(status)); hint != "" {
			out.NextStep += " If it failed because the data is protected: " + hint
		}
	case !out.Done:
		out.NextStep = fmt.Sprintf("Still running. Poll pelican_job_status with job_id %s; do not resubmit.", status.JobID)
	}
	return out
}

type JobListIn struct {
	Status string `json:"status,omitempty" jsonschema:"filter by status: pending, running, completed, failed or cancelled"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of jobs to return (default 20)"`
}

type JobListItemOut struct {
	JobID              string    `json:"job_id"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
	TransfersCompleted int       `json:"transfers_completed"`
	TransfersTotal     int       `json:"transfers_total"`
	BytesTransferred   int64     `json:"bytes_transferred"`
	TotalBytes         int64     `json:"total_bytes"`
}

type JobListOut struct {
	Jobs  []JobListItemOut `json:"jobs"`
	Total int              `json:"total" jsonschema:"total jobs matching the filter, which may exceed those returned"`
}

func (s *Server) handleJobList(ctx context.Context, _ *mcpsdk.CallToolRequest, in JobListIn) (*mcpsdk.CallToolResult, JobListOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, JobListOut{}, err
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > maxJobListLimit {
		limit = maxJobListLimit
	}
	res, err := agent.ListJobs(ctx, in.Status, limit, 0)
	if err != nil {
		return nil, JobListOut{}, errors.Wrap(err, "failed to list transfer jobs")
	}
	out := JobListOut{Total: res.Total, Jobs: make([]JobListItemOut, 0, len(res.Jobs))}
	for _, j := range res.Jobs {
		out.Jobs = append(out.Jobs, JobListItemOut{
			JobID:              j.JobID,
			Status:             j.Status,
			CreatedAt:          j.CreatedAt,
			TransfersCompleted: j.TransfersCompleted,
			TransfersTotal:     j.TransfersTotal,
			BytesTransferred:   j.BytesTransferred,
			TotalBytes:         j.TotalBytes,
		})
	}
	return nil, out, nil
}

type JobCancelIn struct {
	JobID string `json:"job_id" jsonschema:"the job ID to cancel"`
}

type JobCancelOut struct {
	JobID     string `json:"job_id"`
	Cancelled bool   `json:"cancelled"`
}

func (s *Server) handleJobCancel(ctx context.Context, _ *mcpsdk.CallToolRequest, in JobCancelIn) (*mcpsdk.CallToolResult, JobCancelOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, JobCancelOut{}, err
	}
	if err := agent.CancelJob(ctx, in.JobID); err != nil {
		return nil, JobCancelOut{}, errors.Wrapf(err, "failed to cancel job %s", in.JobID)
	}
	return nil, JobCancelOut{JobID: in.JobID, Cancelled: true}, nil
}

// --- credentials ---

type WalletStatusIn struct{}

type WalletStatusOut struct {
	Unlocked             bool   `json:"unlocked" jsonschema:"true if the agent can use stored credentials for protected data"`
	CredentialFileExists bool   `json:"credential_file_exists"`
	Detail               string `json:"detail"`
}

func (s *Server) handleWalletStatus(ctx context.Context, _ *mcpsdk.CallToolRequest, _ WalletStatusIn) (*mcpsdk.CallToolResult, WalletStatusOut, error) {
	agent, err := s.connect(ctx)
	if err != nil {
		return nil, WalletStatusOut{}, err
	}
	status, err := agent.WalletStatus(ctx)
	if err != nil {
		return nil, WalletStatusOut{}, errors.Wrap(err, "failed to query the client agent's wallet")
	}
	out := WalletStatusOut{
		Unlocked:             status.Open,
		CredentialFileExists: status.CredentialFileExists,
	}
	switch {
	case status.Open:
		out.Detail = "The wallet is unlocked; protected namespaces the user holds credentials for are reachable."
	case !status.CredentialFileExists:
		out.Detail = "No Pelican credential file exists yet. Public data works as-is. For protected data the user " +
			"must run `pelican client-agent warm <url>` in a terminal to acquire a credential; it will prompt them " +
			"to create a password protecting it. Do not ask the user for that password -- this server cannot accept it."
	default:
		out.Detail = unlockHint
	}
	return nil, out, nil
}

// jobOperation reports the operation a job was carrying out, so the wallet
// remedy can name the right URLs to warm. A job created here holds exactly one
// transfer; the first is representative for a hand-built multi-transfer job.
func jobOperation(status *client_agent.JobStatus) string {
	if len(status.Transfers) == 0 {
		return ""
	}
	return status.Transfers[0].Operation
}

// walletHint returns the remedy for a locked wallet, or "" when the wallet is
// open or its state cannot be determined.
func (s *Server) walletHint(ctx context.Context, agent agentAPI, operation string) string {
	status, err := agent.WalletStatus(ctx)
	if err != nil || status.Open {
		return ""
	}
	return unlockHintFor(operation)
}

// explain appends the wallet remedy to a failed operation when the wallet is
// locked. The remedy is phrased conditionally because we cannot tell an
// authorization failure apart from an unrelated one here -- a locked wallet is
// a plausible cause, not a diagnosis. The wallet is consulted only on the error
// path, so the success path stays at one round trip.
func (s *Server) explain(ctx context.Context, agent agentAPI, operation string, err error) error {
	if hint := s.walletHint(ctx, agent, operation); hint != "" {
		return errors.Errorf("%v\n\nIf this failed because the data is protected: %s", err, hint)
	}
	return err
}
