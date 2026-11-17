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

package backendcred

import (
	"context"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// FileTokenSource reads a bearer token from a file on every call -- the
// administrator-maintained token file that predates managed credentials.
// Reading every time means a token replaced on disk is picked up at once.
type FileTokenSource struct {
	Path string
}

func (f FileTokenSource) Token(_ context.Context) (string, error) {
	if f.Path == "" {
		return "", nil
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read token file %s", f.Path)
	}
	return strings.TrimSpace(string(data)), nil
}
