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
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

// RegisterAPI adds the administrator endpoints for owner's credentials to
// group:
//
//	GET    <group>                  list credential statuses
//	POST   <group>/:id/activate     start (or show the pending) device flow
//	DELETE <group>/:id              forget the credential
//
// middleware runs first on every route; callers pass their authentication and
// admin-authorization handlers.
func RegisterAPI(group *gin.RouterGroup, reg *Registry, owner string, middleware ...gin.HandlerFunc) {
	h := apiHandlers{reg: reg, owner: owner}
	chain := func(handler gin.HandlerFunc) []gin.HandlerFunc {
		return append(slices.Clone(middleware), handler)
	}
	group.GET("", chain(h.list)...)
	group.POST("/:id/activate", chain(h.activate)...)
	group.DELETE("/:id", chain(h.deactivate)...)
}

type apiHandlers struct {
	reg   *Registry
	owner string
}

func (h apiHandlers) lookup(ctx *gin.Context) *Manager {
	m := h.reg.Get(ctx.Param("id"))
	if m == nil || m.Owner() != h.owner {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No backend credential with that ID",
		})
		return nil
	}
	return m
}

func (h apiHandlers) list(ctx *gin.Context) {
	managers := h.reg.List(h.owner)
	statuses := make([]Status, 0, len(managers))
	for _, m := range managers {
		statuses = append(statuses, m.Status())
	}
	ctx.JSON(http.StatusOK, statuses)
}

func (h apiHandlers) activate(ctx *gin.Context) {
	m := h.lookup(ctx)
	if m == nil {
		return
	}
	actor := ctx.GetString("User")
	st, err := m.BeginDeviceFlow(ctx.Request.Context(), actor)
	if err != nil {
		log.Errorf("Failed to start the device flow for backend credential %s: %v", m.ID(), err)
		// The failure is almost always the issuer's (unreachable, no device
		// grant, registration refused); its message is what the admin needs.
		ctx.JSON(http.StatusBadGateway, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, st)
}

func (h apiHandlers) deactivate(ctx *gin.Context) {
	m := h.lookup(ctx)
	if m == nil {
		return
	}
	if err := m.Deactivate(ctx.Request.Context()); err != nil {
		log.Errorf("Failed to deactivate backend credential %s: %v", m.ID(), err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to deactivate the credential",
		})
		return
	}
	ctx.JSON(http.StatusOK, m.Status())
}
