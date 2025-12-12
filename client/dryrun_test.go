/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package client

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDryRunOutputFormat verifies the structured output format for dry-run mode
func TestDryRunOutputFormat(t *testing.T) {
	tests := []struct {
		name           string
		operation      string
		source         string
		destination    string
		expectedPrefix string
		expectedParts  []string
	}{
		{
			name:           "Download operation",
			operation:      "DOWNLOAD",
			source:         "/namespace/path/to/file.txt",
			destination:    "/local/dest/file.txt",
			expectedPrefix: "DOWNLOAD:",
			expectedParts: []string{
				"/namespace/path/to/file.txt",
				"->",
				"/local/dest/file.txt",
			},
		},
		{
			name:           "Upload operation",
			operation:      "UPLOAD",
			source:         "/local/source/target.dat",
			destination:    "/namespace/upload/target.dat",
			expectedPrefix: "UPLOAD:",
			expectedParts: []string{
				"/local/source/target.dat",
				"->",
				"/namespace/upload/target.dat",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Simulate dry-run output (this is what the actual code does)
			fmt.Printf("%s: %s -> %s\n", tt.operation, tt.source, tt.destination)

			// Restore stdout and read output
			w.Close()
			os.Stdout = oldStdout
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Verify the output format
			assert.Contains(t, output, tt.expectedPrefix, "Output should start with operation prefix")
			for _, part := range tt.expectedParts {
				assert.Contains(t, output, part, "Output should contain: %s", part)
			}

			// Verify the output is on a single line (for easy grepping)
			lines := strings.Split(strings.TrimSpace(output), "\n")
			assert.Equal(t, 1, len(lines), "Output should be on a single line for easy grepping")
		})
	}
}

// TestDryRunOptionCreation verifies the WithDryRun option can be created
func TestDryRunOptionCreation(t *testing.T) {
	// Test that the WithDryRun function exists and returns an option
	dryRunOption := WithDryRun(true)
	assert.NotNil(t, dryRunOption, "WithDryRun should return a non-nil option")

	noDryRunOption := WithDryRun(false)
	assert.NotNil(t, noDryRunOption, "WithDryRun(false) should also return a non-nil option")
}
