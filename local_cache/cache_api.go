/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package local_cache

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type (
	localCacheResp struct {
		Status localCacheResponseStatus `json:"status"`
		Msg    string                   `json:"msg,omitempty"`
	}

	localCacheResponseStatus string
)

const (
	responseOk     localCacheResponseStatus = "success"
	responseFailed localCacheResponseStatus = "error"
)

// Launch the unix socket listener as a separate goroutine
func (lc *LocalCache) LaunchListener(ctx context.Context, egrp *errgroup.Group) (err error) {
	socketName := param.LocalCache_Socket.GetString()
	if err = os.MkdirAll(filepath.Dir(socketName), fs.FileMode(0755)); err != nil {
		err = errors.Wrap(err, "failed to create socket directory")
		return
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketName, Net: "unix"})
	if err != nil {
		return
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		transferStatusStr := r.Header.Get("X-Transfer-Status")
		sendTrailer := false
		if transferStatusStr == "true" {
			for _, encoding := range r.Header.Values("TE") {
				if encoding == "trailers" {
					sendTrailer = true
					w.Header().Set("Trailer", "X-Transfer-Status")
					break
				}
			}
		}

		authzHeader := r.Header.Get("Authorization")
		bearerToken := ""
		if strings.HasPrefix(authzHeader, "Bearer ") {
			bearerToken = authzHeader[7:] // len("Bearer ") == 7
		}
		path := path.Clean(r.URL.Path)

		var size uint64
		var reader io.ReadCloser
		if r.Method == "HEAD" {
			size, err = lc.Stat(path, bearerToken)
			if err == nil {
				w.Header().Set("Content-Length", strconv.FormatUint(size, 10))
			}
		} else {
			reader, err = lc.Get(path, bearerToken)
		}
		if errors.Is(err, authorizationDenied) {
			w.WriteHeader(http.StatusForbidden)
			if _, err = w.Write([]byte("Authorization Denied")); err != nil {
				log.Errorln("Failed to write authorization denied to client")
			}
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err = w.Write([]byte("Unexpected internal error")); err != nil {
				log.Errorln("Failed to write internal error message to client")
			}
			log.Errorln("Failed to get file from cache:", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == "HEAD" {
			return
		}
		if _, err = io.Copy(w, reader); err != nil && sendTrailer {
			// TODO: Enumerate more error values
			w.Header().Set("X-Transfer-Status", fmt.Sprintf("%d: %s", 500, err))
		} else if sendTrailer {
			w.Header().Set("X-Transfer-Status", "200: OK")
		}
	}
	srv := http.Server{
		Handler: http.HandlerFunc(handler),
	}
	egrp.Go(func() error {
		return srv.Serve(listener)
	})
	egrp.Go(func() error {
		<-ctx.Done()
		return srv.Shutdown(ctx)
	})
	return
}

// Register the control & monitoring routines with Gin
func (lc *LocalCache) Register(ctx context.Context, router *gin.RouterGroup) {
	router.POST("/api/v1.0/localcache/purge", func(ginCtx *gin.Context) { lc.purgeCmd(ginCtx) })
}

// Authorize the request then trigger the purge routine
func (lc *LocalCache) purgeCmd(ginCtx *gin.Context) {
	token := ginCtx.GetHeader("Authorization")
	var hasPrefix bool
	if token, hasPrefix = strings.CutPrefix(token, "Bearer "); !hasPrefix {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, localCacheResp{responseFailed, "Bearer token required to authenticate"})
		return
	}

	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusInternalServerError, localCacheResp{responseFailed, "Unable to get local server token issuer"})
		return
	}
	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwks))
	if err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, localCacheResp{responseFailed, "Authorization token cannot be verified"})
	}
	scopeValidator := token_scopes.CreateScopeValidator([]token_scopes.TokenScope{token_scopes.Localcache_Purge}, true)
	if err = jwt.Validate(tok, jwt.WithValidator(scopeValidator)); err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, localCacheResp{responseFailed, "Authorization token is not valid: " + err.Error()})
		return
	}
	lc.purge()
}