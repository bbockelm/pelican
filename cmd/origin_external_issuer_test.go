//go:build server

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
	"testing"

	"github.com/stretchr/testify/assert"
)

// The external-issuer CLI is read-only (issuers are configured, not created via
// the API), so the testable logic is path construction and the shared
// splitAndTrim helper the client-blessing flags rely on.

func TestExternalIssuerAPIPath(t *testing.T) {
	prev := issuerClientNamespace
	t.Cleanup(func() { issuerClientNamespace = prev })
	issuerClientNamespace = "/project"

	assert.Equal(t, "/api/v1.0/issuer/admin/ns/project/external-issuers",
		externalIssuerAPIPath("", ""))
	assert.Equal(t, "/api/v1.0/issuer/admin/ns/project/external-issuers/keycloak",
		externalIssuerAPIPath("keycloak", ""))
	assert.Equal(t, "/api/v1.0/issuer/admin/ns/project/external-issuers/keycloak/probe",
		externalIssuerAPIPath("keycloak", "probe"))
	assert.Equal(t, "/api/v1.0/issuer/admin/ns/project/external-issuers/keycloak/dry-run",
		externalIssuerAPIPath("keycloak", "dry-run"))
}

func TestSplitAndTrim(t *testing.T) {
	assert.Equal(t, []string{}, splitAndTrim(""))
	assert.Equal(t, []string{"a", "b"}, splitAndTrim(" a , b "))
	assert.Equal(t, []string{"a"}, splitAndTrim("a,,"))
}
