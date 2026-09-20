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
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pelicanplatform/pelican/client_agent"
)

// fakeAgent stands in for the client agent so the tools can be exercised
// without a running daemon.
type fakeAgent struct {
	mu sync.Mutex

	statResp *client_agent.StatResponse
	statErr  error

	listResp *client_agent.ListResponse
	listErr  error

	createErr error
	createdID string
	created   []client_agent.TransferRequest

	// statuses is consumed one entry per GetJobStatus call; the last entry
	// repeats once exhausted.
	statuses  []*client_agent.JobStatus
	statusErr error
	statusN   int

	listJobsResp *client_agent.JobListResponse
	cancelErr    error
	cancelled    []string

	walletOpen   bool
	walletExists bool
	walletErr    error
	walletN      int
}

func (f *fakeAgent) CreateJob(_ context.Context, transfers []client_agent.TransferRequest, _ client_agent.TransferOptions) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return "", f.createErr
	}
	f.created = append(f.created, transfers...)
	return f.createdID, nil
}

func (f *fakeAgent) GetJobStatus(_ context.Context, jobID string) (*client_agent.JobStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	idx := f.statusN
	if idx >= len(f.statuses) {
		idx = len(f.statuses) - 1
	}
	f.statusN++
	st := *f.statuses[idx]
	st.JobID = jobID
	return &st, nil
}

func (f *fakeAgent) CancelJob(_ context.Context, jobID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, jobID)
	return f.cancelErr
}

func (f *fakeAgent) ListJobs(_ context.Context, _ string, _, _ int) (*client_agent.JobListResponse, error) {
	return f.listJobsResp, nil
}

func (f *fakeAgent) Stat(_ context.Context, _ string, _ client_agent.TransferOptions) (*client_agent.StatResponse, error) {
	return f.statResp, f.statErr
}

func (f *fakeAgent) List(_ context.Context, _ string, _ client_agent.TransferOptions) (*client_agent.ListResponse, error) {
	return f.listResp, f.listErr
}

func (f *fakeAgent) WalletStatus(_ context.Context) (*client_agent.WalletStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.walletN++
	if f.walletErr != nil {
		return nil, f.walletErr
	}
	return &client_agent.WalletStatusResponse{Open: f.walletOpen, CredentialFileExists: f.walletExists}, nil
}

func (f *fakeAgent) walletCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.walletN
}

// newTestSession wires an in-memory MCP client to a server backed by the given
// fake agent, so tests exercise the real protocol path (schema validation
// included) rather than calling handlers directly.
func newTestSession(t *testing.T, agent *fakeAgent) *mcpsdk.ClientSession {
	t.Helper()

	srv := &Server{agent: agent, version: "test", settleWait: 500 * time.Millisecond}
	clientTransport, serverTransport := mcpsdk.NewInMemoryTransports()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	serverSession, err := srv.MCPServer().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = session.Close()
		_ = serverSession.Wait()
	})
	return session
}

// call invokes a tool and decodes its structured output into out.
func call(t *testing.T, session *mcpsdk.ClientSession, name string, args map[string]any, out any) *mcpsdk.CallToolResult {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	if out != nil && !res.IsError {
		raw, err := json.Marshal(res.StructuredContent)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, out))
	}
	return res
}

// resultText flattens a tool result's content, which is where the SDK puts the
// message for an error result.
func resultText(res *mcpsdk.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcpsdk.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestToolsAdvertised(t *testing.T) {
	session := newTestSession(t, &fakeAgent{})

	res, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)

	got := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
		assert.NotEmpty(t, tool.Description, "tool %s needs a description", tool.Name)
	}
	assert.ElementsMatch(t, []string{
		"pelican_stat",
		"pelican_list",
		"pelican_get",
		"pelican_put",
		"pelican_copy",
		"pelican_job_status",
		"pelican_job_list",
		"pelican_job_cancel",
		"pelican_wallet_status",
	}, got)
}

// TestNoToolAcceptsACredential pins the security property this server is built
// around: the wallet password (and any other bare credential) must never be
// accepted over the MCP transport, because it would land in the assistant's
// conversation transcript or in an MCP client's on-disk config.
func TestNoToolAcceptsACredential(t *testing.T) {
	session := newTestSession(t, &fakeAgent{})

	res, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.Tools)

	forbidden := []string{"password", "passphrase", "secret", "token", "credential"}
	inspected := 0
	for _, tool := range res.Tools {
		schema, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		var parsed struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		require.NoError(t, json.Unmarshal(schema, &parsed))
		for prop := range parsed.Properties {
			inspected++
			for _, bad := range forbidden {
				assert.NotContains(t, strings.ToLower(prop), bad,
					"tool %s accepts a credential-shaped input %q", tool.Name, prop)
			}
		}
	}
	assert.NotZero(t, inspected, "no tool inputs were inspected; the schema shape must have changed")
}

func TestStat(t *testing.T) {
	modTime := time.Date(2026, 5, 15, 23, 41, 38, 0, time.UTC)
	session := newTestSession(t, &fakeAgent{
		statResp: &client_agent.StatResponse{
			Name:      "/ospool/public/test.txt",
			Size:      14,
			ModTime:   modTime,
			Checksums: map[string]string{"crc32c": "deadbeef"},
		},
	})

	var out StatOut
	res := call(t, session, "pelican_stat", map[string]any{"url": "osdf:///ospool/public/test.txt"}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Equal(t, "/ospool/public/test.txt", out.Name)
	assert.Equal(t, int64(14), out.Size)
	assert.False(t, out.IsCollection)
	assert.Equal(t, modTime, out.ModTime.UTC())
	assert.Equal(t, "deadbeef", out.Checksums["crc32c"])
}

func TestList(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		listResp: &client_agent.ListResponse{Items: []client_agent.ListItem{
			{Name: "a.txt", Size: 1},
			{Name: "sub", IsCollection: true},
		}},
	})

	var out ListOut
	res := call(t, session, "pelican_list", map[string]any{"url": "osdf:///ospool/public"}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Equal(t, 2, out.Count)
	require.Len(t, out.Items, 2)
	assert.Equal(t, "a.txt", out.Items[0].Name)
	assert.True(t, out.Items[1].IsCollection)
}

// TestGetCompletesWithinSettleWindow covers the small-transfer case: the job
// finishes while the tool is still waiting, so the caller gets a terminal
// result in one round trip instead of a job ID to poll.
func TestGetCompletesWithinSettleWindow(t *testing.T) {
	agent := &fakeAgent{
		createdID: "job-1",
		statuses: []*client_agent.JobStatus{
			{Status: client_agent.StatusRunning},
			{
				Status:   client_agent.StatusCompleted,
				Progress: &client_agent.JobProgress{BytesTransferred: 14, TotalBytes: 14, TransfersCompleted: 1, TransfersTotal: 1},
				Transfers: []client_agent.TransferStatus{{
					Operation: "get", Source: "osdf:///a", Destination: "/tmp/a",
					Status: client_agent.StatusCompleted, BytesTransferred: 14, TotalBytes: 14,
				}},
			},
		},
	}
	session := newTestSession(t, agent)

	var out JobOut
	res := call(t, session, "pelican_get", map[string]any{
		"source": "osdf:///a", "destination": "/tmp/a",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Equal(t, "job-1", out.JobID)
	assert.True(t, out.Done)
	assert.Equal(t, client_agent.StatusCompleted, out.Status)
	assert.Equal(t, int64(14), out.BytesTransferred)
	assert.Empty(t, out.NextStep, "a finished job should not ask the assistant to poll")

	require.Len(t, agent.created, 1)
	assert.Equal(t, "get", agent.created[0].Operation)
}

// TestPutReturnsJobIDWhenSlow covers the reason transfers are asynchronous:
// an upload that outlives the settle window must hand back a job ID and tell
// the assistant to poll, never to resubmit.
func TestPutReturnsJobIDWhenSlow(t *testing.T) {
	agent := &fakeAgent{
		createdID: "job-2",
		statuses: []*client_agent.JobStatus{{
			Status:   client_agent.StatusRunning,
			Progress: &client_agent.JobProgress{BytesTransferred: 1 << 20, TotalBytes: 1 << 30, TransfersTotal: 1},
		}},
	}
	session := newTestSession(t, agent)

	var out JobOut
	res := call(t, session, "pelican_put", map[string]any{
		"source": "/tmp/big.dat", "destination": "osdf:///protected/big.dat",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Equal(t, "job-2", out.JobID)
	assert.False(t, out.Done)
	assert.Equal(t, client_agent.StatusRunning, out.Status)
	assert.Contains(t, out.NextStep, "job-2")
	assert.Contains(t, out.NextStep, "do not resubmit")

	require.Len(t, agent.created, 1)
	assert.Equal(t, "put", agent.created[0].Operation)
	assert.Equal(t, "/tmp/big.dat", agent.created[0].Source)
}

func TestJobStatusPoll(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		statuses: []*client_agent.JobStatus{{
			Status:   client_agent.StatusCompleted,
			Progress: &client_agent.JobProgress{TransfersCompleted: 2, TransfersTotal: 2},
		}},
	})

	var out JobOut
	res := call(t, session, "pelican_job_status", map[string]any{"job_id": "job-3"}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Equal(t, "job-3", out.JobID)
	assert.True(t, out.Done)
	assert.Equal(t, 2, out.TransfersCompleted)
}

func TestJobCancel(t *testing.T) {
	agent := &fakeAgent{}
	session := newTestSession(t, agent)

	var out JobCancelOut
	res := call(t, session, "pelican_job_cancel", map[string]any{"job_id": "job-4"}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.True(t, out.Cancelled)
	assert.Equal(t, []string{"job-4"}, agent.cancelled)
}

func TestJobListClampsLimit(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		listJobsResp: &client_agent.JobListResponse{
			Total: 3,
			Jobs:  []client_agent.JobListItem{{JobID: "a"}, {JobID: "b"}, {JobID: "c"}},
		},
	})

	var out JobListOut
	res := call(t, session, "pelican_job_list", map[string]any{"limit": 10000}, &out)
	require.False(t, res.IsError, resultText(res))
	assert.Equal(t, 3, out.Total)
	assert.Len(t, out.Jobs, 3)
}

// TestLockedWalletExplainsFailure checks that an operation that fails while the
// wallet is locked comes back with the out-of-band remedy attached, and that
// the remedy never invites the assistant to collect a password.
func TestLockedWalletExplainsFailure(t *testing.T) {
	agent := &fakeAgent{
		statErr:      errors.New("403 Forbidden"),
		walletOpen:   false,
		walletExists: true,
	}
	session := newTestSession(t, agent)

	res := call(t, session, "pelican_stat", map[string]any{"url": "osdf:///protected/x"}, nil)
	require.True(t, res.IsError, "a failed stat should be reported as a tool error")

	text := resultText(res)
	assert.Contains(t, text, "403 Forbidden", "the underlying failure must survive")
	assert.Contains(t, text, "pelican client-agent warm")
	assert.Contains(t, text, "cannot accept it")
	// The remedy is a hypothesis, not a diagnosis: we cannot tell an
	// authorization failure from an unrelated one at this layer.
	assert.Contains(t, text, "If this failed because the data is protected")
	assert.Less(t, strings.Index(text, "403 Forbidden"), strings.Index(text, "client-agent warm"),
		"the actual error should lead, with the remedy after it")
}

// TestSuccessPathSkipsWalletCheck pins the round-trip cost: the wallet is only
// consulted when something actually failed.
func TestSuccessPathSkipsWalletCheck(t *testing.T) {
	agent := &fakeAgent{statResp: &client_agent.StatResponse{Name: "/public/x", Size: 1}}
	session := newTestSession(t, agent)

	res := call(t, session, "pelican_stat", map[string]any{"url": "osdf:///public/x"}, nil)
	require.False(t, res.IsError, resultText(res))
	assert.Zero(t, agent.walletCalls(), "the happy path should not query the wallet")
}

// TestOpenWalletDoesNotAddHint guards against telling the user to unlock a
// wallet that is already unlocked when a transfer fails for an unrelated reason.
func TestOpenWalletDoesNotAddHint(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		statErr:      errors.New("404 Not Found"),
		walletOpen:   true,
		walletExists: true,
	})

	res := call(t, session, "pelican_stat", map[string]any{"url": "osdf:///public/missing"}, nil)
	require.True(t, res.IsError)

	text := resultText(res)
	assert.Contains(t, text, "404 Not Found")
	assert.NotContains(t, text, "client-agent warm")
}

func TestWalletStatus(t *testing.T) {
	for _, tc := range []struct {
		name         string
		open         bool
		exists       bool
		wantUnlocked bool
		wantDetail   string
	}{
		{"unlocked", true, true, true, "unlocked"},
		{"locked", false, true, false, "pelican client-agent warm"},
		{"no credential file", false, false, false, "No Pelican credential file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := newTestSession(t, &fakeAgent{walletOpen: tc.open, walletExists: tc.exists})

			var out WalletStatusOut
			res := call(t, session, "pelican_wallet_status", map[string]any{}, &out)
			require.False(t, res.IsError, resultText(res))

			assert.Equal(t, tc.wantUnlocked, out.Unlocked)
			assert.Equal(t, tc.exists, out.CredentialFileExists)
			assert.Contains(t, out.Detail, tc.wantDetail)
		})
	}
}

// TestSubmitSurvivesLostStatus checks that a job whose status lookup fails
// right after submission is still reported as submitted; losing track of it
// must not read as "nothing happened" and invite a duplicate upload.
func TestSubmitSurvivesLostStatus(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		createdID: "job-5",
		statusErr: errors.New("socket closed"),
	})

	var out JobOut
	res := call(t, session, "pelican_put", map[string]any{
		"source": "/tmp/x", "destination": "osdf:///p/x",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Equal(t, "job-5", out.JobID)
	assert.Contains(t, out.NextStep, "job-5")
	assert.Contains(t, out.NextStep, "pelican_job_status")
}

// TestMissingRequiredArgument confirms the SDK rejects malformed calls against
// the generated schema before a handler runs.
func TestMissingRequiredArgument(t *testing.T) {
	session := newTestSession(t, &fakeAgent{})

	res, err := session.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "pelican_get",
		Arguments: map[string]any{"source": "osdf:///a"},
	})
	require.NoError(t, err, "schema validation should surface as a tool error, not a protocol error")
	require.True(t, res.IsError, "a call missing 'destination' should not succeed")
	assert.Contains(t, resultText(res), "destination")
}

// --- third-party copy ---

// TestCopySubmitsThirdPartyCopy checks that a remote-to-remote copy reaches the
// agent as a "copy" operation, which is what routes it to the client's
// third-party-copy path instead of streaming the bytes through this machine.
func TestCopySubmitsThirdPartyCopy(t *testing.T) {
	agent := &fakeAgent{
		createdID: "job-tpc",
		statuses: []*client_agent.JobStatus{{
			Status:   client_agent.StatusRunning,
			Progress: &client_agent.JobProgress{TotalBytes: 1 << 30, TransfersTotal: 1},
			Transfers: []client_agent.TransferStatus{{
				Operation: "copy", Source: "osdf:///src/a", Destination: "osdf:///dst/a",
				Status: client_agent.StatusRunning,
			}},
		}},
	}
	session := newTestSession(t, agent)

	var out JobOut
	res := call(t, session, "pelican_copy", map[string]any{
		"source": "osdf:///src/a", "destination": "osdf:///dst/a",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	require.Len(t, agent.created, 1)
	assert.Equal(t, "copy", agent.created[0].Operation)
	assert.Equal(t, "osdf:///src/a", agent.created[0].Source)
	assert.Equal(t, "osdf:///dst/a", agent.created[0].Destination)
	assert.False(t, agent.created[0].Recursive)

	assert.Equal(t, "job-tpc", out.JobID)
	assert.False(t, out.Done)
	assert.Contains(t, out.NextStep, "job-tpc")
}

func TestCopyRecursive(t *testing.T) {
	agent := &fakeAgent{
		createdID: "job-tpc-r",
		statuses:  []*client_agent.JobStatus{{Status: client_agent.StatusCompleted}},
	}
	session := newTestSession(t, agent)

	res := call(t, session, "pelican_copy", map[string]any{
		"source": "pelican://example.org/src", "destination": "pelican://example.org/dst", "recursive": true,
	}, nil)
	require.False(t, res.IsError, resultText(res))

	require.Len(t, agent.created, 1)
	assert.True(t, agent.created[0].Recursive)
}

// TestCopyRejectsLocalPaths pins the guard against the client's habit of
// silently degrading a half-local copy into a get or a put: pelican_copy is
// only for federation-to-federation transfers, and a wrong tool choice should
// be named rather than papered over.
func TestCopyRejectsLocalPaths(t *testing.T) {
	for _, tc := range []struct {
		name        string
		source      string
		destination string
		wantField   string
		wantTool    string
	}{
		{"local source", "/tmp/a", "osdf:///dst/a", "source", "pelican_put"},
		{"local destination", "osdf:///src/a", "/tmp/a", "destination", "pelican_get"},
		{"file scheme source", "file:///tmp/a", "osdf:///dst/a", "source", "pelican_put"},
		{"https source", "https://example.org/a", "osdf:///dst/a", "source", "pelican_put"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := &fakeAgent{createdID: "unused"}
			session := newTestSession(t, agent)

			res := call(t, session, "pelican_copy", map[string]any{
				"source": tc.source, "destination": tc.destination,
			}, nil)
			require.True(t, res.IsError, "a half-local copy should be refused")

			text := resultText(res)
			assert.Contains(t, text, tc.wantField)
			assert.Contains(t, text, tc.wantTool, "the error should point at the right tool")
			assert.Empty(t, agent.created, "nothing should reach the agent")
		})
	}
}

// TestCopyWalletHintNamesBothSides covers the credential asymmetry that makes
// third-party copy easy to get wrong: it needs a read credential for the source
// and a write credential for the destination, so a remedy naming only one side
// would leave the user stuck after following it.
func TestCopyWalletHintNamesBothSides(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		createdID:    "job-tpc-fail",
		walletOpen:   false,
		walletExists: true,
		statuses: []*client_agent.JobStatus{{
			Status: client_agent.StatusFailed,
			Error:  "403 Forbidden",
			Transfers: []client_agent.TransferStatus{{
				Operation: "copy", Source: "osdf:///src/a", Destination: "osdf:///protected/a",
				Status: client_agent.StatusFailed, Error: "403 Forbidden",
			}},
		}},
	})

	var out JobOut
	res := call(t, session, "pelican_copy", map[string]any{
		"source": "osdf:///src/a", "destination": "osdf:///protected/a",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	require.True(t, out.Done)
	assert.Equal(t, client_agent.StatusFailed, out.Status)
	assert.Contains(t, out.NextStep, "both sides")
	assert.Contains(t, out.NextStep, "--write")
	assert.Contains(t, out.NextStep, "client-agent warm")
}

// TestPutWalletHintMentionsWrite is the companion case: an upload needs only
// the destination warmed, and with --write.
func TestPutWalletHintMentionsWrite(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		createdID:    "job-put-fail",
		walletOpen:   false,
		walletExists: true,
		statuses: []*client_agent.JobStatus{{
			Status: client_agent.StatusFailed,
			Transfers: []client_agent.TransferStatus{{
				Operation: "put", Source: "/tmp/a", Destination: "osdf:///protected/a",
				Status: client_agent.StatusFailed,
			}},
		}},
	})

	var out JobOut
	res := call(t, session, "pelican_put", map[string]any{
		"source": "/tmp/a", "destination": "osdf:///protected/a",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Contains(t, out.NextStep, "--write")
	assert.NotContains(t, out.NextStep, "both sides", "an upload has only one side to warm")
}

// TestGetWalletHintStaysGeneric guards the default branch: a download should
// not be told to warm anything with --write.
func TestGetWalletHintStaysGeneric(t *testing.T) {
	session := newTestSession(t, &fakeAgent{
		createdID:    "job-get-fail",
		walletOpen:   false,
		walletExists: true,
		statuses: []*client_agent.JobStatus{{
			Status: client_agent.StatusFailed,
			Transfers: []client_agent.TransferStatus{{
				Operation: "get", Source: "osdf:///protected/a", Destination: "/tmp/a",
				Status: client_agent.StatusFailed,
			}},
		}},
	})

	var out JobOut
	res := call(t, session, "pelican_get", map[string]any{
		"source": "osdf:///protected/a", "destination": "/tmp/a",
	}, &out)
	require.False(t, res.IsError, resultText(res))

	assert.Contains(t, out.NextStep, "client-agent warm")
	assert.NotContains(t, out.NextStep, "both sides")
	assert.NotContains(t, out.NextStep, "This was an upload")
}
