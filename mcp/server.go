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

// Package mcp exposes the Pelican client to AI assistants over the Model
// Context Protocol, speaking JSON-RPC on stdio.
//
// The server holds no credentials of its own. Every operation is delegated to
// the user's client agent over its unix socket, so transfers run
// asynchronously (surviving the short tool-call timeouts MCP clients impose)
// and tokens are acquired, cached, and refreshed by the agent's wallet.
//
// This division exists because an MCP server is spawned by an AI assistant
// without a controlling terminal: it can neither prompt for the credential
// file's password nor run an interactive OAuth flow. The wallet password is
// never passed to this process and never crosses the MCP transport. Instead
// the user unlocks the agent's wallet out of band from a real terminal with
// `pelican client-agent warm <url>`; this server only reports when that is
// needed. See client_agent/wallet.go for the wallet's side of the contract.
package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/config"
)

const (
	serverName = "pelican"

	// defaultSettleWait is how long a transfer tool waits for a freshly
	// submitted job to finish before handing the job ID back to the caller to
	// poll. Small transfers thus complete in a single tool call, while long
	// ones return promptly instead of burning the client's tool-call timeout.
	defaultSettleWait = 10 * time.Second

	// settlePollInterval is how often a settling job is polled. The agent is
	// on a local unix socket, so this is cheap.
	settlePollInterval = 250 * time.Millisecond

	// agentStartRetries bounds how long we wait for a cold agent to accept
	// connections after we spawn it.
	agentStartRetries = 5
)

// agentAPI is the slice of the client agent's API this server uses. It is an
// interface so the tool handlers can be tested against a fake agent.
type agentAPI interface {
	CreateJob(ctx context.Context, transfers []client_agent.TransferRequest, options client_agent.TransferOptions) (string, error)
	GetJobStatus(ctx context.Context, jobID string) (*client_agent.JobStatus, error)
	CancelJob(ctx context.Context, jobID string) error
	ListJobs(ctx context.Context, status string, limit, offset int) (*client_agent.JobListResponse, error)
	Stat(ctx context.Context, url string, options client_agent.TransferOptions) (*client_agent.StatResponse, error)
	List(ctx context.Context, url string, options client_agent.TransferOptions) (*client_agent.ListResponse, error)
	WalletStatus(ctx context.Context) (*client_agent.WalletStatusResponse, error)
}

// Server adapts the Pelican client agent to the Model Context Protocol.
type Server struct {
	// mu guards lazy initialization of agent.
	mu    sync.Mutex
	agent agentAPI

	// settleWait overrides defaultSettleWait; zero means use the default.
	settleWait time.Duration

	// version is reported to the MCP client during initialization.
	version string
}

// NewServer returns an MCP server that delegates to the user's client agent.
// The agent connection is established lazily on the first tool call so that a
// failure to reach it surfaces as a tool error the assistant can explain,
// rather than killing the server during the initialize handshake.
func NewServer() *Server {
	return &Server{version: config.GetVersion()}
}

// SetSettleWait overrides how long transfer tools wait for a new job to finish
// before returning its ID for polling. Intended for tests.
func (s *Server) SetSettleWait(d time.Duration) { s.settleWait = d }

// settleTimeout reports the effective settle wait.
func (s *Server) settleTimeout() time.Duration {
	if s.settleWait > 0 {
		return s.settleWait
	}
	return defaultSettleWait
}

// connect returns the client agent, starting it if it is not already running.
func (s *Server) connect(ctx context.Context) (agentAPI, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agent != nil {
		return s.agent, nil
	}
	client, err := apiclient.EnsureRunning(ctx, agentStartRetries)
	if err != nil {
		return nil, errors.Wrap(err, "failed to reach the Pelican client agent")
	}
	s.agent = client
	return s.agent, nil
}

// MCPServer builds the underlying protocol server with all Pelican tools
// registered.
func (s *Server) MCPServer() *mcpsdk.Server {
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:        serverName,
		Title:       "Pelican",
		Description: "Browse and transfer objects in a Pelican data federation such as the OSDF.",
		Version:     s.version,
	}, nil)
	s.registerTools(srv)
	return srv
}

// Run serves the Model Context Protocol on stdin/stdout until the client
// disconnects or ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	log.Debug("Pelican MCP server starting on stdio")
	return s.MCPServer().Run(ctx, &mcpsdk.StdioTransport{})
}
