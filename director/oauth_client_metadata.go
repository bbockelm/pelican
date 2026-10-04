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

package director

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/oauth2/backendcred"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// How long an authorization server may cache a client ID metadata document.
// The document only changes with the federation's URLs; key rotation and
// revocation flow through the registry JWKS it points to, so a day-scale
// cache is not needed to make either take effect and an hour keeps a
// director move from lingering.
const clientIDMetadataDocumentMaxAge = "public, max-age=3600"

// serveClientIDMetadataDocument serves the OAuth client ID metadata document
// for the federation server whose registry prefix follows
// backendcred.ClientIDMetadataDocumentPath, e.g.
// /api/v1.0/director/oauthClients/caches/<sitename>.
//
// The document's URL is that server's OAuth client_id when it acquires a
// long-lived backend credential with the device flow.  It describes a
// confidential client whose keys are the server's registered keys, served
// by the registry; the registry serves those only for registered (and, if
// the federation requires it, approved) servers, so publishing a document
// for an arbitrary well-formed name grants nothing -- nobody can
// authenticate as a client whose keys the registry does not have.  That is
// why the director does not consult the registry here, and so keeps
// answering for a server whose advertisement has lapsed (an authorization
// server re-fetches the document when the server refreshes its token).
func serveClientIDMetadataDocument(ctx *gin.Context) {
	if param.Director_DisableClientIDMetadataDocuments.GetBool() {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "This director does not publish OAuth client metadata documents",
		})
		return
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		log.Errorf("Cannot serve an OAuth client metadata document: federation discovery failed: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Federation discovery failed",
		})
		return
	}
	federationName := ""
	if u, err := url.Parse(fedInfo.DiscoveryEndpoint); err == nil && u.Host != "" {
		federationName = u.Hostname()
	}
	doc, err := backendcred.NewClientIDMetadataDocument(fedInfo.DirectorEndpoint, fedInfo.RegistryEndpoint,
		ctx.Param("serverPrefix"), federationName)
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No client metadata document for that server: " + err.Error(),
		})
		return
	}
	ctx.Header("Cache-Control", clientIDMetadataDocumentMaxAge)
	ctx.JSON(http.StatusOK, doc)
}
