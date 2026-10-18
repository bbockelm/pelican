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

package origin

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oauth2/backendcred"
	"github.com/pelicanplatform/pelican/origin_serve"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// The admin API and the backendcred registry know the origin's credentials
// by this owner.
const backendCredentialOwner = "origin"

// usesManagedHTTPSCredential reports whether the origin's HTTPS/WebDAV backend
// gets its token from a device-flow credential (Origin.HttpAuthOAuth2DeviceFlow).
func usesManagedHTTPSCredential() bool {
	ost := server_structs.OriginStorageType(param.Origin_StorageType.GetString())
	return (ost == server_structs.OriginStorageHTTPS || ost == server_structs.OriginStorageHTTPSv2) &&
		param.Origin_HttpAuthOAuth2DeviceFlow.GetBool()
}

// ManagedHTTPSTokenFile is where the XRootD-backed https origin finds the
// access token of its managed credential, or "" when the origin does not
// use one.  XRootD's HTTP plugin re-reads the file every few seconds, so the
// refreshes the credential manager writes there take effect without a
// restart -- the same arrangement the Globus backend uses.
func ManagedHTTPSTokenFile() string {
	if !usesManagedHTTPSCredential() ||
		server_structs.OriginStorageType(param.Origin_StorageType.GetString()) != server_structs.OriginStorageHTTPS {
		return ""
	}
	return filepath.Join(param.Origin_RunLocation.GetString(), "backend-credentials", origin_serve.HTTPSBackendCredentialID+".tok")
}

// originClientIDMetadataDocumentURL is this origin's client_id under the
// director's client ID metadata documents, or "" if it has none (a
// standalone origin, or federation discovery failed).
func originClientIDMetadataDocumentURL(ctx context.Context) string {
	if config.IsStandaloneOrigin() {
		return ""
	}
	fedInfo, err := config.GetFederation(ctx)
	if err != nil || fedInfo.DirectorEndpoint == "" {
		log.Debugf("No director to publish a client ID metadata document for this origin: %v", err)
		return ""
	}
	extURL, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil || extURL.Host == "" {
		return ""
	}
	clientID, err := backendcred.ClientIDMetadataDocumentURL(fedInfo.DirectorEndpoint, server_structs.GetOriginNs(extURL.Host))
	if err != nil {
		log.Debugf("Cannot derive a client ID metadata document URL for this origin: %v", err)
		return ""
	}
	return clientID
}

// InitBackendCredentials creates and starts the managed credential of the
// origin's HTTPS/WebDAV backend when Origin.HttpAuthOAuth2DeviceFlow is set.
// It must run after the server database is initialized and before the
// storage backends and the XRootD configuration are built, both of which
// look the credential up.
func InitBackendCredentials(ctx context.Context, egrp *errgroup.Group) error {
	if !usesManagedHTTPSCredential() {
		return nil
	}

	cfg := backendcred.Config{
		ID:                          origin_serve.HTTPSBackendCredentialID,
		Owner:                       backendCredentialOwner,
		DisplayName:                 "HTTPS backend " + param.Origin_HttpServiceUrl.GetString(),
		Issuer:                      param.Origin_HttpAuthOAuth2Issuer.GetString(),
		Scopes:                      param.Origin_HttpAuthOAuth2Scopes.GetStringSlice(),
		Audience:                    param.Origin_HttpAuthOAuth2Audience.GetString(),
		ClientID:                    param.Origin_HttpAuthOAuth2ClientID.GetString(),
		RegistrationMode:            backendcred.ClientRegistrationMode(param.Origin_HttpAuthOAuth2ClientRegistration.GetString()),
		ClientIDMetadataDocumentURL: originClientIDMetadataDocumentURL(ctx),
		SigningKey:                  func() (jwk.Key, error) { return config.GetIssuerPrivateJWK() },
		ClientName:                  "Pelican origin " + param.Server_ExternalWebUrl.GetString(),
	}
	if cfg.ClientID == "" && param.Origin_HttpAuthOAuth2ClientSecretFile.GetString() != "" {
		log.Warningf("%s is ignored because %s is not set",
			param.Origin_HttpAuthOAuth2ClientSecretFile.GetName(), param.Origin_HttpAuthOAuth2ClientID.GetName())
	}
	if secretFile := param.Origin_HttpAuthOAuth2ClientSecretFile.GetString(); cfg.ClientID != "" && secretFile != "" {
		secret, err := os.ReadFile(secretFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read %s", param.Origin_HttpAuthOAuth2ClientSecretFile.GetName())
		}
		cfg.ClientSecret = strings.TrimSpace(string(secret))
	}

	if tokenFile := ManagedHTTPSTokenFile(); tokenFile != "" {
		sink, err := xrootdTokenSink(tokenFile)
		if err != nil {
			return err
		}
		cfg.TokenSink = sink
	}

	mgr, err := backendcred.NewManager(cfg, backendcred.NewDBStore(database.ServerDatabase))
	if err != nil {
		return err
	}
	if err := mgr.Start(ctx, egrp); err != nil {
		return errors.Wrap(err, "failed to start the HTTPS backend credential")
	}
	if err := backendcred.Default().Add(mgr); err != nil {
		return err
	}
	if st := mgr.Status(); st.State != backendcred.StateActive {
		log.Warningf("The origin's HTTPS backend credential is not active (%s); an administrator must activate it from the web UI", st.Message)
	}
	return nil
}

// xrootdTokenSink prepares the directory for tokenFile and returns a sink
// that writes each new access token there for XRootD, and removes the file
// when the credential stops being usable so that XRootD fails requests
// instead of sending a stale or empty token.
func xrootdTokenSink(tokenFile string) (func(string) error, error) {
	puser, err := config.GetPelicanUser()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the pelican user")
	}
	xrootdGid, err := config.GetDaemonGID()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the xrootd gid")
	}
	if err := server_utils.PrepareTokenDir(filepath.Dir(tokenFile), puser.Uid, xrootdGid); err != nil {
		return nil, err
	}
	return func(token string) error {
		if token == "" {
			if err := os.Remove(tokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
		return server_utils.WriteDaemonTokenFile(tokenFile, token)
	}, nil
}
