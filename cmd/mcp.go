//go:build client

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

package main

import (
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/mcp"
)

var (
	mcpCmd = &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol (MCP) server for the Pelican client",
		Long: `Expose the Pelican client to AI assistants over the Model Context Protocol.

The server speaks JSON-RPC on stdin/stdout and is meant to be launched by an MCP
client (Claude Code, VS Code Copilot, and similar) rather than run by hand.

Transfers are delegated to the Pelican client agent, which runs them
asynchronously; the assistant receives a job ID it can poll. Credentials are
likewise the agent's responsibility: this server never handles the password
protecting your credential file. To reach protected data, unlock the agent's
wallet from a terminal first with 'pelican client-agent warm <url>'.`,
	}

	mcpServeCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server on stdio",
		Long: `Start the Model Context Protocol server, reading JSON-RPC requests from stdin
and writing responses to stdout. Logs go to stderr so they cannot corrupt the
protocol stream.`,
		SilenceUsage: true,
		RunE:         runMCPServe,
	}
)

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	// stdout carries the JSON-RPC stream; everything else must go to stderr.
	log.SetOutput(os.Stderr)

	if err := config.InitClient(); err != nil {
		return errors.Wrap(err, "failed to initialize the Pelican client")
	}

	if err := mcp.NewServer().Run(cmd.Context()); err != nil {
		return errors.Wrap(err, "MCP server failed")
	}
	return nil
}
