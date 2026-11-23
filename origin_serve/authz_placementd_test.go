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

package origin_serve

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/placementd"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const (
	placementdTestIssuer   = "pool.example.com"
	placementdTestIdentity = "alice@pool.example.com"
	// placementdTestToken stands in for an IDToken. The stub verifier below
	// never looks at it: what this file exercises is everything that
	// happens once an identity is known.
	placementdTestToken = "placementd-token"
)

// stubVerifier answers as a placement daemon would, without one.
type stubVerifier struct {
	recognize bool
	identity  placementd.Identity
	err       error
	calls     int
}

func (s *stubVerifier) Recognize(string) bool { return s.recognize }

func (s *stubVerifier) Verify(context.Context, string) (placementd.Identity, error) {
	s.calls++
	if s.err != nil {
		return placementd.Identity{}, s.err
	}
	return s.identity, nil
}

// newPlacementdTestDB brings up a real origin database — the production
// migrations, so users, groups, collections and their ACLs behave as they do
// in a deployment — and installs it as the process database the authorization
// code reads.
func newPlacementdTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	setStringParamForTest(t, param.Server_DbLocation, filepath.Join(t.TempDir(), "pelican.sqlite"))
	prev := database.ServerDatabase
	t.Cleanup(func() { database.ServerDatabase = prev })
	require.NoError(t, database.InitServerDatabase(server_structs.OriginType))
	return database.ServerDatabase
}

// seedPlacementdUser creates a Pelican user and, unless link is false, the
// identity row an administrator adds to associate the placement daemon's
// identity with them.
func seedPlacementdUser(t *testing.T, db *gorm.DB, username string, link bool) *database.User {
	t.Helper()
	user := &database.User{
		ID:        username + "-id",
		Username:  username,
		Sub:       username,
		Issuer:    "https://idp.example.com",
		Status:    database.UserStatusActive,
		CreatedBy: "test",
	}
	require.NoError(t, db.Create(user).Error)
	if link {
		require.NoError(t, db.Create(&database.UserIdentity{
			ID:     username + "-identity",
			UserID: user.ID,
			Sub:    placementdTestIdentity,
			Issuer: placementdTestIssuer,
		}).Error)
	}
	return user
}

// setAuthzTemplates installs Issuer.AuthorizationTemplates and recompiles
// them. The compiled rules live in a package global that is only populated at
// startup, so a test that changes the templates has to recompile or it would
// be authorized by whatever a previous test left behind.
func setAuthzTemplates(t *testing.T, templates []map[string]any) {
	t.Helper()
	prev := param.Issuer_AuthorizationTemplates.GetRaw()
	require.NoError(t, param.Issuer_AuthorizationTemplates.Set(templates))
	require.NoError(t, oa4mp.InitAuthzRules())
	t.Cleanup(func() {
		_ = param.Issuer_AuthorizationTemplates.Set(prev)
		_ = oa4mp.InitAuthzRules()
	})
}

// newPlacementdAuthConfig wires an auth config with the stub verifier in place
// of a placement daemon.
func newPlacementdAuthConfig(t *testing.T, exports []server_utils.OriginExport, stub *stubVerifier) *authConfig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})
	ac := newAuthConfig(ctx, egrp)
	t.Cleanup(func() {
		if ac.userMapper != nil {
			ac.userMapper.Shutdown()
		}
	})
	ac.placementd = stub
	ac.placementdIssuer = placementdTestIssuer
	require.NoError(t, ac.updateConfig(exports))
	return ac
}

// readWriteExport is an export that permits both, so a refusal in these tests
// is the authorization decision talking and not a capability.
func readWriteExport(prefix, storage string) server_utils.OriginExport {
	return server_utils.OriginExport{
		FederationPrefix: prefix,
		StoragePrefix:    storage,
		IssuerUrls:       []string{"https://issuer.example.com"},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
	}
}

func scopeStrings(in acls) []string {
	out := make([]string, 0, len(in))
	for _, scope := range in {
		out = append(out, string(scope.Authorization)+":"+scope.Resource)
	}
	return out
}

// TestPlacementdTokenAuthorizesViaTemplates is the core of the design: the
// placement daemon says who the caller is, and Pelican's own authorization
// templates say what they may do.
func TestPlacementdTokenAuthorizesViaTemplates(t *testing.T) {
	db := newPlacementdTestDB(t)
	user := seedPlacementdUser(t, db, "alice", true)

	require.NoError(t, db.Create(&database.Group{
		ID: "g-physics", Name: "physics", CreatedBy: "test", OwnerID: user.ID,
		AuthTemplateEligible: true,
	}).Error)
	require.NoError(t, db.Create(&database.GroupMember{
		GroupID: "g-physics", UserID: user.ID, AddedBy: "test",
	}).Error)

	setAuthzTemplates(t, []map[string]any{
		{"actions": []string{"read"}, "prefix": "/shared", "groups": []string{"physics"}},
		{"actions": []string{"read", "write"}, "prefix": "/home/$USER", "users": []string{"alice"}},
		{"actions": []string{"read"}, "prefix": "/astro", "groups": []string{"astronomy"}},
	})

	stub := &stubVerifier{
		recognize: true,
		identity:  placementd.Identity{Subject: placementdTestIdentity, Expiration: time.Now().Add(time.Hour)},
	}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

	info, ttl, err := ac.placementdTokenInfo(placementdTestToken)
	require.NoError(t, err)
	assert.Equal(t, 1, stub.calls)
	assert.Equal(t, placementdTestIssuer, info.Issuer,
		"the entry must record where the identity came from")
	require.NotNil(t, info.UserInfo)
	assert.Equal(t, "alice", info.UserInfo.User,
		"with no mapfile configured the data plane acts as the resolved Pelican user")
	assert.Equal(t, time.Duration(0), ttl,
		"a token outliving the authorization cache should use the cache's own timeout")

	scopes := scopeStrings(info.Scopes)
	assert.Contains(t, scopes, "storage.read:/exp/shared", "a group-matched template must grant through the export prefix")
	assert.Contains(t, scopes, "storage.read:/exp/home/alice", "$USER must expand to the resolved Pelican user")
	assert.Contains(t, scopes, "storage.modify:/exp/home/alice")
	assert.NotContains(t, scopes, "storage.read:/exp/astro",
		"a template for a group the user is not in must grant nothing")

	// And the decision the data plane actually asks for. The first of these
	// populates the authorization cache; none of the rest may reach the
	// daemon again.
	verifications := stub.calls
	assert.True(t, ac.authorize(token_scopes.Wlcg_Storage_Read, "/exp/home/alice/data.txt", placementdTestToken))
	assert.True(t, ac.authorize(token_scopes.Wlcg_Storage_Modify, "/exp/home/alice/data.txt", placementdTestToken))
	assert.False(t, ac.authorize(token_scopes.Wlcg_Storage_Modify, "/exp/shared/data.txt", placementdTestToken),
		"a read-only template must not confer writes")
	assert.False(t, ac.authorize(token_scopes.Wlcg_Storage_Read, "/exp/somebody-else/data.txt", placementdTestToken))
	assert.Equal(t, verifications+1, stub.calls, "the authorization decision must be cached, not re-verified per request")
}

// TestPlacementdTokenAuthorizesViaCollectionAcls covers the other half of what
// the user is entitled to: a collection somebody shared with their group.
func TestPlacementdTokenAuthorizesViaCollectionAcls(t *testing.T) {
	db := newPlacementdTestDB(t)
	user := seedPlacementdUser(t, db, "alice", true)
	owner := seedPlacementdUser(t, db, "bob", false)

	require.NoError(t, db.Create(&database.Group{
		ID: "g-writers", Name: "proj-writers", CreatedBy: "test", OwnerID: owner.ID,
	}).Error)
	require.NoError(t, db.Create(&database.GroupMember{
		GroupID: "g-writers", UserID: user.ID, AddedBy: "test",
	}).Error)
	require.NoError(t, db.Create(&database.Collection{
		ID: "c-proj", Name: "proj", OwnerID: owner.ID,
		Namespace: "/exp/proj", Visibility: database.VisibilityPrivate,
	}).Error)
	require.NoError(t, db.Create(&database.CollectionACL{
		CollectionID: "c-proj", SubjectType: database.ACLSubjectGroup,
		SubjectID: "g-writers", Role: database.AclRoleWrite, GrantedBy: owner.ID,
	}).Error)

	// No templates at all: whatever the user gets here comes from the ACL.
	setAuthzTemplates(t, nil)

	stub := &stubVerifier{recognize: true, identity: placementd.Identity{Subject: placementdTestIdentity}}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

	info, _, err := ac.placementdTokenInfo(placementdTestToken)
	require.NoError(t, err)

	scopes := scopeStrings(info.Scopes)
	assert.Contains(t, scopes, "storage.read:/exp/proj", "a write ACL implies reads on the collection's namespace")
	assert.Contains(t, scopes, "storage.modify:/exp/proj")
	for _, scope := range scopes {
		assert.NotContains(t, scope, "collection.",
			"collection management scopes belong to the web API and are meaningless as filesystem ACLs")
	}
}

// TestPlacementdTokenRespectsExportCapabilities: an identity's entitlements
// cannot talk an export into doing something it is not configured for.
func TestPlacementdTokenRespectsExportCapabilities(t *testing.T) {
	db := newPlacementdTestDB(t)
	seedPlacementdUser(t, db, "alice", true)
	setAuthzTemplates(t, []map[string]any{
		{"actions": []string{"read", "write"}, "prefix": "/home/$USER", "users": []string{"alice"}},
	})

	readOnly := readWriteExport("/ro", t.TempDir())
	readOnly.Capabilities.Writes = false

	stub := &stubVerifier{recognize: true, identity: placementd.Identity{Subject: placementdTestIdentity}}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readOnly}, stub)

	info, _, err := ac.placementdTokenInfo(placementdTestToken)
	require.NoError(t, err)
	scopes := scopeStrings(info.Scopes)
	assert.Contains(t, scopes, "storage.read:/ro/home/alice")
	assert.NotContains(t, scopes, "storage.modify:/ro/home/alice",
		"a write-disabled export stays write-disabled whatever the user is entitled to")
}

// TestPlacementdTokenRequiresALinkedIdentity is the rule that keeps the
// placement daemon from being an account factory: it authenticates, it does
// not enroll.
func TestPlacementdTokenRequiresALinkedIdentity(t *testing.T) {
	db := newPlacementdTestDB(t)
	setAuthzTemplates(t, []map[string]any{
		{"actions": []string{"read"}, "prefix": "/", "users": []string{"alice"}},
	})

	t.Run("no identity row", func(t *testing.T) {
		seedPlacementdUser(t, db, "alice", false)
		stub := &stubVerifier{recognize: true, identity: placementd.Identity{Subject: placementdTestIdentity}}
		ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

		_, _, err := ac.placementdTokenInfo(placementdTestToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not linked to any Pelican user")
		assert.False(t, ac.authorize(token_scopes.Wlcg_Storage_Read, "/exp/anything", placementdTestToken),
			"an unlinked identity must be refused, not served as some default user")
	})

	t.Run("identity recorded under another issuer", func(t *testing.T) {
		// The same subject under a different issuer is a different
		// identity; matching on the subject alone would let any issuer
		// Pelican trusts impersonate a placement-daemon identity.
		user := seedPlacementdUser(t, db, "carol", false)
		require.NoError(t, db.Create(&database.UserIdentity{
			ID: "carol-identity", UserID: user.ID,
			Sub: placementdTestIdentity, Issuer: "https://elsewhere.example.com",
		}).Error)
		stub := &stubVerifier{recognize: true, identity: placementd.Identity{Subject: placementdTestIdentity}}
		ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

		_, _, err := ac.placementdTokenInfo(placementdTestToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not linked to any Pelican user")
	})
}

// TestPlacementdTokenRefusedForInactiveUser: disabling the Pelican account has
// to disable the placement-daemon token with it.
func TestPlacementdTokenRefusedForInactiveUser(t *testing.T) {
	db := newPlacementdTestDB(t)
	user := seedPlacementdUser(t, db, "alice", true)
	require.NoError(t, db.Model(user).Update("status", database.UserStatusInactive).Error)
	setAuthzTemplates(t, []map[string]any{
		{"actions": []string{"read"}, "prefix": "/", "users": []string{"alice"}},
	})

	stub := &stubVerifier{recognize: true, identity: placementd.Identity{Subject: placementdTestIdentity}}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

	_, _, err := ac.placementdTokenInfo(placementdTestToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inactive")
}

// TestPlacementdVerificationFailureIsNotAuthorized: a refusal from the daemon
// must not fall through to the ordinary token path or to a default user.
func TestPlacementdVerificationFailureIsNotAuthorized(t *testing.T) {
	db := newPlacementdTestDB(t)
	seedPlacementdUser(t, db, "alice", true)
	setAuthzTemplates(t, []map[string]any{
		{"actions": []string{"read"}, "prefix": "/", "users": []string{"alice"}},
	})

	stub := &stubVerifier{recognize: true, err: errors.Wrap(placementd.ErrRefused, "forged")}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

	_, _, err := ac.placementdTokenInfo(placementdTestToken)
	assert.ErrorIs(t, err, placementd.ErrRefused)
	assert.False(t, ac.authorize(token_scopes.Wlcg_Storage_Read, "/exp/anything", placementdTestToken))
}

// TestUnrecognizedTokenSkipsThePlacementDaemon: the recognition gate is what
// keeps the daemon out of the path of every other token this origin serves.
func TestUnrecognizedTokenSkipsThePlacementDaemon(t *testing.T) {
	db := newPlacementdTestDB(t)
	seedPlacementdUser(t, db, "alice", true)
	setAuthzTemplates(t, nil)

	stub := &stubVerifier{recognize: false, identity: placementd.Identity{Subject: placementdTestIdentity}}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

	assert.False(t, ac.authorize(token_scopes.Wlcg_Storage_Read, "/exp/anything", "some-other-token"))
	assert.Zero(t, stub.calls, "a token the verifier does not recognize must never be sent to the placement daemon")
}

// TestPublicReadsStillApply: a public export is readable by a
// placement-daemon-authenticated caller like anyone else.
func TestPlacementdTokenGetsPublicReads(t *testing.T) {
	db := newPlacementdTestDB(t)
	seedPlacementdUser(t, db, "alice", true)
	setAuthzTemplates(t, nil)

	public := readWriteExport("/pub", t.TempDir())
	public.Capabilities.PublicReads = true

	stub := &stubVerifier{recognize: true, identity: placementd.Identity{Subject: placementdTestIdentity}}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{public}, stub)

	info, _, err := ac.placementdTokenInfo(placementdTestToken)
	require.NoError(t, err)
	assert.Contains(t, scopeStrings(info.Scopes), "storage.read:/pub")
}

// TestPlacementdTokenInfoClampsToTokenExpiry: the authorization must not
// outlive the credential that established it.
func TestPlacementdTokenInfoClampsToTokenExpiry(t *testing.T) {
	db := newPlacementdTestDB(t)
	seedPlacementdUser(t, db, "alice", true)
	setAuthzTemplates(t, nil)

	stub := &stubVerifier{recognize: true, identity: placementd.Identity{
		Subject:    placementdTestIdentity,
		Expiration: time.Now().Add(30 * time.Second),
	}}
	ac := newPlacementdAuthConfig(t, []server_utils.OriginExport{readWriteExport("/exp", t.TempDir())}, stub)

	_, ttl, err := ac.placementdTokenInfo(placementdTestToken)
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, 30*time.Second)
	assert.Less(t, ttl, tokenAuthzTTL)

	stub.identity.Expiration = time.Now().Add(-time.Second)
	_, _, err = ac.placementdTokenInfo(placementdTestToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// TestInitPlacementdConfiguration covers the startup contract: no address
// means the feature is off, and the identity issuer defaults to the pool's
// trust domain.
func TestInitPlacementdConfiguration(t *testing.T) {
	newConfig := func(t *testing.T) *authConfig {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(ctx)
		t.Cleanup(func() {
			cancel()
			_ = egrp.Wait()
		})
		ac := newAuthConfig(ctx, egrp)
		t.Cleanup(func() {
			if ac.userMapper != nil {
				ac.userMapper.Shutdown()
			}
		})
		require.NoError(t, ac.initPlacementd(ctx, egrp))
		return ac
	}

	t.Run("off by default", func(t *testing.T) {
		setStringParamForTest(t, param.Origin_Placementd_Address, "")
		ac := newConfig(t)
		assert.Nil(t, ac.placementd,
			"the nil check in the loader is what keeps the feature off, so a typed nil here would turn it on")
	})

	t.Run("identity issuer defaults to the trust domain", func(t *testing.T) {
		setStringParamForTest(t, param.Origin_Placementd_Address, "placement.example.com:9618")
		setStringParamForTest(t, param.Origin_Placementd_TrustDomain, placementdTestIssuer)
		setStringParamForTest(t, param.Origin_Placementd_IdentityIssuer, "")
		ac := newConfig(t)
		require.NotNil(t, ac.placementd)
		assert.Equal(t, placementdTestIssuer, ac.placementdIssuer)
	})

	t.Run("identity issuer can be configured", func(t *testing.T) {
		setStringParamForTest(t, param.Origin_Placementd_Address, "placement.example.com:9618")
		setStringParamForTest(t, param.Origin_Placementd_TrustDomain, placementdTestIssuer)
		setStringParamForTest(t, param.Origin_Placementd_IdentityIssuer, "https://ap.example.com")
		ac := newConfig(t)
		require.NotNil(t, ac.placementd)
		assert.Equal(t, "https://ap.example.com", ac.placementdIssuer)
	})

	t.Run("an address without a trust domain fails startup", func(t *testing.T) {
		setStringParamForTest(t, param.Origin_Placementd_Address, "placement.example.com:9618")
		setStringParamForTest(t, param.Origin_Placementd_TrustDomain, "")
		ctx, cancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(ctx)
		t.Cleanup(func() {
			cancel()
			_ = egrp.Wait()
		})
		ac := newAuthConfig(ctx, egrp)
		t.Cleanup(func() {
			if ac.userMapper != nil {
				ac.userMapper.Shutdown()
			}
		})
		require.Error(t, ac.initPlacementd(ctx, egrp))
	})
}
