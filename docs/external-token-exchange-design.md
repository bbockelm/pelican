# External Token Exchange for the Pelican Issuer

> **Status:** Implemented. Server, admin diagnostics API, CLI, and web UI are in place with tests. This document is both the design rationale and the reference for what shipped.
>
> **Configuration model:** trusted external issuers are defined in configuration (`Origin.Exports[*].ExternalIssuers`, with the global `Issuer.ExternalIssuers` as a fallback), not in the database. They are trust anchors — deciding whose tokens become Pelican identities — so they belong under git change-control alongside the rest of the origin's config, and are parsed and validated at startup. The database holds only the per-client blessing (`oidc_clients.allow_external_exchange`), because clients are created at runtime. The admin REST/CLI/UI surfaces are therefore read-only for issuers (list plus the probe/dry-run diagnostics); the blessing is the one mutable piece.
>
> **Scope:** external OAuth2 token exchange (RFC 8693) at the origin's embedded issuer — presenting a token from a trusted foreign issuer and receiving a Pelican WLCG token. Depends on globally-unique usernames and the unified `user_identities` model.
>
> **Scope:** Extends the origin's embedded OIDC issuer (`oauth2/issuer/`) so that an access token minted by a *trusted external* OAuth2 issuer can be exchanged (RFC 8693) for a Pelican-issued WLCG-profile access token. Does not change the data plane (XRootD/`origin_serve` token validation) or the federation issuer.

## 1. Motivation

A collaborating project runs its own Keycloak instance and a JupyterHub.

1. A user logs into JupyterHub; JupyterHub obtains a Keycloak access token for that user with a project-specific scope.
1. JupyterHub holds a confidential OAuth2 client registered with the Pelican origin, blessed for token exchange.
1. JupyterHub presents the Keycloak access token as the `subject_token` to the Pelican origin's token endpoint and receives a Pelican access token (WLCG common JWT profile) carrying `storage.read:/…`-style scopes.
1. The notebook then uses that Pelican token for data access exactly as if the user had gone through the browser authorization-code flow.

The value is that the collaboration's users never see a second login: their existing Keycloak session becomes Pelican storage authorization. The cost is that Pelican must decide, carefully, how much of a foreign IdP's assertions it is willing to believe.

## 2. What already exists

A surprising amount of this is already in `main`; the gap is narrower than it first looks.

| Capability                                  | Status today                                                                                               | Where                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| RFC 8693 token-exchange grant on the issuer | **Exists**, but the `subject_token` must be a token this server itself issued                              | `oauth2/issuer/admin_handlers.go:356` (`handleTokenExchange`)                          |
| Grant advertised in discovery metadata      | **Exists** (`grant_types_supported`)                                                                       | `oauth2/issuer/handlers.go:250`                                                        |
| Blessing a client for token exchange        | **Exists** — `grant_types` includes `urn:ietf:params:oauth:grant-type:token-exchange`                      | `oauth2/issuer/storage.go`, `cmd/origin_client.go`                                     |
| CLI for issuer clients                      | **Exists** — `pelican-server origin issuer client create/list/update/delete`                               | `cmd/origin_client.go`                                                                 |
| REST for issuer clients                     | **Exists** — `/api/v1.0/issuer/admin/ns/<ns>/clients[/{id}]`                                               | `oauth2/issuer/handlers.go:1420`                                                       |
| `(issuer, sub)` → local user lookup         | **Exists** — resolves against `user_identities`, the sole identity table                                   | `database.GetUserByIdentity`                                                           |
| Additional identity mappings per user       | **Exists** in DB, REST (`/users/{id}/identities`) and CLI (`pelican-server user identity add/list/remove`) | `database/collection.go:3487`, `web_ui/ui.go:846`, `cmd/server_users_groups.go:856`    |
| Group claim name configuration              | **Exists**, but only for the single web-login IdP                                                          | `Issuer.OIDCGroupClaim`, `Issuer.GroupSource`                                          |
| Remote JWKS discovery + caching             | **Exists** as a reusable pattern                                                                           | `token.LookupIssuerJwksUrl` (`token/token_create.go:444`), `origin_serve/authz.go:144` |
| Mapping user+groups → storage scopes        | **Exists**                                                                                                 | `oa4mp.CalculateAllowedScopesWithRules`, `oa4mp.GetUserCollectionScopes`               |

What is missing:

- The concept of a **trusted external issuer** as a first-class, per-namespace, admin-managed object.
- Verification of a `subject_token` that this server did **not** sign.
- Per-client restriction of **which** external issuers a client may exchange from.
- Group extraction from a foreign token, with a trust boundary around foreign group names.
- Web UI for linking an identity to a user (the UI lists and unlinks, but cannot add — `web_ui/frontend/app/settings/users/edit/view.tsx:509`).

## 3. Flow

```
JupyterHub                     Pelican origin issuer                 Keycloak
    |                                   |                               |
    |-- POST /api/v1.0/issuer/ns/<ns>/token                             |
    |     grant_type=…token-exchange    |                               |
    |     subject_token=<keycloak AT>   |                               |
    |     client_id/secret (JupyterHub) |                               |
    |---------------------------------->|                               |
    |                                   | 1. authenticate client        |
    |                                   | 2. peek `iss` of subject_token|
    |                                   | 3. resolve trusted ext issuer |
    |                                   |    (per-namespace DB row)     |
    |                                   | 4. fetch/refresh JWKS ------->|
    |                                   |<------------------------------|
    |                                   | 5. verify sig/exp/aud/scope   |
    |                                   | 6. (iss,sub) -> local user    |
    |                                   | 7. groups from claim + local  |
    |                                   | 8. run the SAME authz         |
    |                                   |    pipeline as /authorize     |
    |                                   | 9. mint WLCG JWT              |
    |<----------------------------------|                               |
    |   access_token (Pelican, WLCG)    |                               |
```

Steps 8 and 9 are the point of the whole design: the exchanged token's scopes are **computed from Pelican's own authorization rules for the mapped local user**, not copied from the Keycloak token. The Keycloak token is an authentication assertion, never an authorization one.

## 4. Data model

### 4.1 External issuers (configuration)

An external issuer is a configuration object, not a database row. Each origin export may carry its own `ExternalIssuers` list; a global `Issuer.ExternalIssuers` provides the fallback, and a per-export list overrides it for that namespace (the same precedence `AuthorizationTemplates` uses). At startup each entry is decoded and run through the same validate path the code would have used for an API create — `applyInput`/`validateDetail` in `oauth2/issuer/external_issuer.go` — so a bad configuration fails the launch with a clear message, and the two deliberately-dangerous acknowledgments (`AllowAnyAudience`, `AllowFlatGroups`) become explicit, git-reviewed fields.

```yaml
Origin:
  Exports:
    - FederationPrefix: /project
      ExternalIssuers:
        - Name: keycloak
          IssuerURL: https://keycloak.example.org/realms/project
          RequiredAudiences: [pelican-origin]
          RequiredClaims: {azp: jupyterhub}
          AutoEnroll: true
          GroupMode: claim        # or "mapped" (with GroupMappings) / "ignore"
          GroupPrefix: "keycloak:"
```

The parsed, validated issuers are stored on the per-namespace `OIDCProvider` (`SetExternalIssuers`), and the exchange resolves a subject token's `iss` against that in-memory list (`ExternalIssuerByURL`) — no database round-trip. Group mappings for `mapped` mode are configured inline on the issuer (`GroupMappings`) rather than in a side table.

### 4.2 Client blessing (`oidc_clients.allow_external_exchange`)

The one piece that stays in the database is a boolean on the client: may this client exchange tokens from external issuers at all? It is all-or-none — a blessed client may present tokens from any of the namespace's configured issuers; the default (false) means it may exchange only tokens this server itself issued, which is what every client that merely holds the token-exchange grant has. Clients live in the database because they are created at runtime (dynamic registration, admin API), so the blessing does too; the issuers they may reach are fixed by configuration.

### 4.3 Identity mappings

No schema change. `user_identities` already carries `(user_id, sub, issuer)` with the two invariants we need — globally unique `(sub, issuer)`, and at most one identity per issuer per user (`database/collection.go:3487`). The Keycloak issuer URL is just another `issuer` value in that table.

## 5. Verifying the subject token

`handleTokenExchange` gains a dispatch step before introspection.

1. Parse the JWT **without verifying** and read `iss`. A token that does not parse as a JWT, or that has no `iss`, falls through to the existing local-introspection path (which handles opaque local tokens).
1. If `iss` equals the local issuer URL for this namespace, take the existing path unchanged.
1. Otherwise resolve an **enabled** configured external issuer in this namespace whose `IssuerURL` matches `iss` exactly (string equality after normalizing a single trailing slash — no prefix matching, no host-only matching), via `ExternalIssuerByURL` over the provider's config list. If there is none, return `invalid_grant`; do not disclose whether the issuer is known-but-disabled.
1. Check the calling client's `allow_external_exchange` flag. If false, return `unauthorized_client`.
1. Resolve the JWKS: `JWKSURL` if set, otherwise `token.LookupIssuerJwksUrl` against `<iss>/.well-known/openid-configuration`. Cache with the `ttlcache` + `jwk.NewCache`/`jwk.NewCachedSet` pattern already used in `origin_serve/authz.go:144` (15-minute TTL, 15-minute minimum refresh, `config.GetBasicTransport`). Negative results are cached for 5 minutes so a dead IdP cannot turn every exchange request into an outbound fetch.
1. Verify: signature, `alg` ∈ `AllowedAlgorithms` (never `none`, never a symmetric algorithm — an HMAC-accepting verifier plus a public JWKS is the classic key-confusion bug), `exp`, `nbf`/`iat` with the codebase's existing clock-skew allowance, `iss` exact match again against the verified claims.
1. Apply the row's policy: `aud` must intersect `RequiredAudiences`; `scope` must contain every entry of `RequiredScopes`; each `RequiredClaims` key must be present with the exact value.

`RequiredAudiences` deserves emphasis. Without it, *any* token Keycloak issues to *any* of its clients — including ones the Pelican operator has never heard of — is a valid `subject_token`. The API should refuse to create a row with an empty `RequiredAudiences` unless the caller passes an explicit `allowAnyAudience: true`, and the UI should render that state as a warning.

Only `subject_token_type` values `urn:ietf:params:oauth:token-type:access_token` and `urn:ietf:params:oauth:token-type:jwt` are accepted. `id_token` is deliberately excluded in phase 1: ID tokens are audienced to the *client*, not to a resource server, and accepting them invites confused-deputy problems.

## 6. Identity resolution

### 6.1 Mapping the external subject to a local user

With verified claims in hand:

1. `sub := claims[row.SubjectClaim]` (string, or a numeric coerced to a string as `web_ui/oauth2_client.go:357` already does for GitHub-style IdPs).
1. `user, err := database.GetUserByIdentity(db, sub, iss)`.
1. On `ErrRecordNotFound`:
   - if `AutoEnroll` is false → `invalid_grant`, "no Pelican account is linked to this identity";
   - if true → `database.LookupOrBootstrapUser(db, sub, iss, displayName, usernameCandidates)` with candidates drawn from `UsernameClaims` (defaults `preferred_username`, `email`, `nickname`).
1. Reject users whose `Status` is not active, or that are soft-deleted — the same revocation check `web_ui.AuthHandler` performs on cookies (`web_ui/authentication.go:615`).

**Recommendation: `AutoEnroll` defaults to true**, with the reasoning that adding the external issuer row *is* the trust decision, and Pelican already self-enrolls users on first login through the configured web IdP (`CreatorSelfEnrolled`). Requiring an admin to pre-link every JupyterHub user would make the feature unusable for the collaboration that asked for it. Operators who want a closed roster set it to false and pre-link with `pelican-server user identity add`. This is the design decision most worth an explicit yes/no before implementation.

Auto-enrolled users are created with a distinct creator sentinel (e.g. `CreatorExternalExchange` plus the external-issuer row ID in `CreatorAuthMethodID`) so an admin can later audit or bulk-remove everything one IdP dragged in.

Auto-enroll should *not* attempt to match an incoming identity to an existing account by email or any other claim. Claim-based account linking is the classic IdP account-takeover hole: whoever controls the `email` claim at the foreign IdP controls which local account they land on. An identity is either already linked or it is new.

**Defaulting `AutoEnroll` to true depends on the global-username constraint in §6.2.**

### 6.2 Username collisions across issuers

Usernames were not globally unique: the constraint was `UNIQUE(username, issuer)`, and `LookupOrBootstrapUser`'s collision-suffix walk only fires on a unique-constraint error, which never occurred across two different issuers. Bootstrapping `("cilogon-sub", "https://cilogon.org")` and then `("kc-sub", "https://kc.example.org/realms/proj")` with the same username candidate produced **two live accounts both named `alice`**.

That mattered because the username is bearer authority in exactly the way group names are: `Issuer.AuthorizationTemplates` interpolates `$USER` into object prefixes. With `AutoEnroll` on, the `preferred_username` claim at a foreign IdP would have been the only thing between an outsider and another user's home prefix.

**Resolved.** Usernames are globally unique (`UNIQUE(username)` among live rows), so the collision-suffix walk in `LookupOrBootstrapUser` fires across issuers and a second `alice` becomes `alice-XXXX`. `AutoEnroll` therefore ships defaulting to true.

### 6.3 Correcting a bad enrollment

If auto-enroll creates an account that should have been a link to an existing one, an admin needs to move the identity.

This used to be genuinely hard, for reasons that had nothing to do with token exchange: identities lived in two places. A user's *primary* identity sat inline on the `users` row and the rest in `user_identities`, and an auto-enrolled account's identity was always the primary one — the case that could not be unlinked at all. Worse, the two tables could disagree. `CreateUserIdentity` never checked other users' primary rows, so relinking an already-claimed identity wrote a row that `GetUserByIdentity` (which consulted `users` first) then ignored, reporting success while changing nothing. The mirror image also held: `LookupOrBootstrapUser` consulted only `users`, so an identity an admin *had* linked was invisible to web login and the user's next sign-in minted a second account.

**Both are fixed by unifying identities** into a single table, an independently useful change. `user_identities` is now the only home, both invariants are ordinary unique indexes, and correcting a mis-enrollment is a single-row update via `database.AdoptUserIdentity`, which refuses if the target already holds an identity at that issuer. Nothing is deleted, so whatever the stray account accumulated survives for the admin to deal with separately.

Making the wrong-account case *visible* matters as much as making it fixable: auto-enrolled accounts are stamped `CreatorExternalExchange` with the issuer's row ID, so an admin can review everything one external issuer enrolled.

## 7. Group resolution

Groups come from up to two sources, unioned:

1. **The external token**, when `GroupMode == "claim"`: read `claims[row.GroupClaim]`, accepting either a JSON array of strings or a comma-separated string, exactly as `web_ui/oauth2_client.go:461` already does. Filter through `GroupAllowPatterns`, then prefix each surviving name with `GroupPrefix`.
1. **The local database**, when `IncludeLocalGroups` is true: `database.GetMemberGroups(db, user.ID)`, unprefixed.

The prefix is the trust boundary, and it matters more than it looks. Group names are *bearer authority* in Pelican: `Issuer.AuthorizationTemplates` interpolates `$GROUP` into object prefixes, and `Server.*AdminGroups` names groups by string. Without a prefix, a Keycloak administrator can mint a group called `sysadmins` or one matching some other tenant's `prefix: /projects/$GROUP` template and walk straight into authority the Pelican operator never granted. `GroupPrefix` is a free-form per-issuer string, not a fixed scheme: it defaults to the issuer row's `Name` followed by `:`, so the operator writes templates against `keycloak:cms`, but any value works — `kc/`, `proj-`, or whatever reads well in that deployment's templates. Setting it to the empty string gives flat, unprefixed group names; because that merges a foreign IdP's namespace into Pelican's authority namespace, it requires `AllowFlatGroups`, the same kind of explicit acknowledgment `AllowAnyAudience` provides for audiences.

The distinction between *omitted* and *explicitly empty* is load-bearing and is why `ExternalIssuerInput` uses pointers throughout. An omitted prefix on create takes the default; an explicitly empty one is refused unless acknowledged; and an update that does not mention the prefix leaves a deliberately-flat configuration alone rather than silently reinstating the default.

One consequence worth stating: the default `:` separator survives into scope strings, so a group `cms` under a `/data/$GROUP` template yields `storage.read:/data/keycloak:cms`. That is unambiguous — every scope parser in the codebase splits on the first colon only (`SplitN(s, ":", 2)`) — and `TestExternalExchangeHappyPath` pins it.

Two hard rules, enforced in code rather than by configuration:

- Groups derived from an external token never satisfy `Server.AdminGroups` / `Server.UIAdminGroups`, and never grant `server.admin` or any `web_ui` scope. An exchanged token is a data-access credential; it is not a route into server administration.
- Groups derived from an external token never make a group *auth-template eligible* — that bit stays admin-set, per `docs/user-group-design.md`.

## 8. Scope computation

This is where the external path rejoins the existing code. The scope pipeline `handleAuthorize` uses is factored into a shared helper — `(*OIDCProvider).authorizeUser(user, userID, groups)` returning a `userAuthorization`, whose `grantable(requested, clientScopes)` narrows a request — in `oauth2/issuer/scope_pipeline.go`. The authorization-code flow, the device-code flow, and the exchange all call it, so the three cannot compute authorizations differently. It covers `CalculateAllowedScopesWithRules` (or the global-rules fallback), `GetUserCollectionScopes`, and the `transferAccessAllowed` gate for `pelican.transfer`.

The granted set is then the intersection of:

- the scopes requested in the exchange request (or everything allowed, if `scope` is absent);
- the computed `allowed` set, with the same broader-request-to-narrower-grant substitution `handleAuthorize` performs;
- the calling client's configured `Scopes` list.

Note what is *absent*: the subject token's own scopes. For a local exchange, subsetting against the subject token is right — the subject token is a Pelican grant being attenuated. For an external exchange it is meaningless, because Keycloak's scope vocabulary is not Pelican's. `RequiredScopes` on the issuer row is where "the JupyterHub token must carry the project scope" gets enforced, and it is a precondition rather than an input to scope computation.

## 9. The issued token

- Audience: `WLCGAudienceAny` only. The local exchange path validates a requested `audience` against the subject token's own granted audiences; a foreign token makes no such statement about Pelican services, so there is nothing to validate against. Rather than invent a second rule, the external path ignores the parameter and grants the wildcard, which every WLCG service accepts. If narrowing turns out to be wanted, it should arrive as an explicit per-issuer allow-list rather than as trust in the request.
- `wlcg.groups`: the matched groups from §7-§8, i.e. the ones that actually drove an authorization, consistent with the authorization-code path.
- Lifetime: `min(Issuer.AccessTokenLifetime, row.MaxTokenLifetimeSeconds, time until subject-token exp)`; an exchange whose subject token is already expiring is refused rather than issuing a zero-length token. The last clause is what keeps a Pelican token from outliving the Keycloak assertion that justified it.
- `act` (RFC 8693 §4.1): `{"sub": <external sub>, "iss": <external iss>}`, recording the provenance of the exchange. Harmless to WLCG consumers and invaluable when reading logs.
- Refresh tokens: issued only when `AllowRefresh` is true **and** `offline_access` was requested **and** the client has the `refresh_token` grant. **Default false.** A refresh token here is an offline credential that survives the user's Keycloak session, their group changes, and their departure from the project; that is a real thing to want, but it should be a deliberate choice per issuer, not a side effect of a scope string.
- Chaining: a token minted by an external exchange is a local token, so it can be re-exchanged through the existing local path. That is acceptable (attenuation only), but the `act` claim should be preserved across the local exchange so provenance is not laundered.

## 10. Surfaces

### 10.1 REST

Read-only, under the existing admin prefix and middleware (`AuthHandler` + `AdminAuthHandler`). External issuers are configured, not created here.

| Method | Path                                                             | Purpose                                                                                                                                                                           |
| ------ | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/v1.0/issuer/admin/ns/<ns>/external-issuers`                | List the configured trusted external issuers                                                                                                                                      |
| POST   | `/api/v1.0/issuer/admin/ns/<ns>/external-issuers/{name}/probe`   | Fetch discovery + JWKS now, report key count, algorithms, and errors                                                                                                              |
| POST   | `/api/v1.0/issuer/admin/ns/<ns>/external-issuers/{name}/dry-run` | Body: a sample subject token. Returns the verdict, the resolved user (or "would auto-enroll as X"), the groups, and the scopes that *would* be granted — without minting anything |

Issuers are addressed by their configured `Name`. The `dry-run` endpoint is the difference between this feature being debuggable and being a black box; it calls `resolveExternalExchange` — the same function a live exchange calls — so what it reports is what would actually happen. Both `probe` and `dry-run` report failures in the response body with `ok: false` rather than as HTTP error statuses.

The client blessing is the one mutable surface: the client create/update payloads carry `allow_external_token_exchange` (a boolean), reusing the existing `/clients` admin API.

Unchanged: `/users/{id}/identities` (GET/POST/DELETE) covers identity mappings.

### 10.2 CLI

Under the existing `pelican-server origin issuer` tree — read-only, since issuers are configured:

```
pelican-server origin issuer external-issuer list    --namespace /project
pelican-server origin issuer external-issuer probe   --namespace /project --name keycloak
pelican-server origin issuer external-issuer dry-run --namespace /project --name keycloak \
      --token-file ./at.jwt

pelican-server origin issuer client update --id <client> \
      --grant-types "urn:ietf:params:oauth:grant-type:token-exchange" \
      --allow-external-exchange
```

Identity mapping is covered by `pelican-server user identity add|list|remove|adopt`.

### 10.3 Web UI

1. **Origin → Issuer** gains a read-only "Trusted external issuers" panel below the config form. Each row shows the issuer's URL and its key settings as chips (group mode/prefix, auto-enroll, and warning chips for the two acknowledged-dangerous states — any-audience and unprefixed groups), plus two diagnostics: **probe** (fetch discovery/JWKS now) and **test a token** (`dry-run`). There is no add/edit/delete — the issuers come from configuration; to change them, edit the config and restart.
1. **Client blessing** is the one editable control: a dialog lists the namespace's OAuth2 clients and toggles each one's `allow_external_token_exchange` flag. Clients lacking the token-exchange grant are shown disabled, since blessing one would do nothing.
1. **Settings → Users → Edit** gains a "Link an identity" form. If the identity is already claimed, the server answers 409 and the button becomes **"Move it here"** — the `adopt` flow — with an explanation that the other account is kept. The section's copy no longer describes a "primary" identity, which no longer exists.

The panel needs to know which namespaces have an issuer, which depends on which exports require authentication rather than on any single config value. `GET /api/v1.0/issuer/admin/namespaces` reports them; the namespace selector appears only when there is more than one.

## 11. Configuration

Trusted external issuers are **configuration**, not database state. They are trust anchors — they decide whose tokens become Pelican identities — so they belong in `pelican.yaml` under the same git change-control as every other origin setting, reviewed in a PR and applied on restart. This is the opposite of the original plan (runtime-editable DB rows); the deciding input was the operations team's, and it is the right call for something this security-sensitive: less visibility and no change-control were exactly the wrong properties for a trust anchor.

The shape is `Origin.Exports[*].ExternalIssuers` per namespace, with `Issuer.ExternalIssuers` as the global fallback (a per-export list overrides the global one for that namespace, mirroring `AuthorizationTemplates`). Entries are validated at startup — including the two acknowledgment flags that gate the dangerous states — so a misconfiguration fails the launch loudly. See §4.1 for the schema and an example.

The only database state is the per-client `allow_external_exchange` flag (§4.2), because clients are created at runtime.

One additional parameter, a kill switch:

```yaml
name: Issuer.DisableExternalTokenExchange
description: |+
  Disable exchanging access tokens issued by trusted external issuers for
  tokens from this server's embedded issuer.  When true, the token-exchange
  grant accepts only subject tokens this server itself issued, regardless of
  any configured trusted external issuers.
type: bool
default: false
components: ["origin"]
```

With no external issuers configured, the feature is inert and the kill switch has no effect.

## 12. Security considerations

| Threat                                                                                  | Mitigation                                                                                                                                                                                  |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Any token from the trusted IdP works, including ones minted for unrelated clients       | `RequiredAudiences` (and optionally `azp` in `RequiredClaims`); config validation refuses an empty audience list without an explicit override                                               |
| Foreign IdP admin squats a privileged group name                                        | `GroupPrefix` namespacing; external groups can never grant admin scopes or auth-template eligibility                                                                                        |
| Foreign IdP claim squats an existing **username**, capturing a `$USER` prefix           | Globally-unique username check on the auto-enrollment path (§6.2) — a prerequisite for `AutoEnroll: true`                                                                                   |
| Wrongly enrolled account cannot be corrected, or is "corrected" silently without effect | Identity unification: both invariants are unique indexes, and `AdoptUserIdentity` moves an identity in one step (§6.3)                                                                      |
| Algorithm/key confusion                                                                 | `AllowedAlgorithms` allow-list, asymmetric only; `alg` checked before verification                                                                                                          |
| Issuer spoofing via lookalike URL                                                       | Exact `iss` string match against the configured issuer; no prefix or host matching                                                                                                          |
| Blast radius of a compromised client                                                    | `allow_external_exchange` is per-client and false by default; client scope list still bounds the result                                                                                     |
| Pelican access outliving the external session                                           | Token lifetime capped by the subject token's `exp`; refresh tokens off by default                                                                                                           |
| Outbound-fetch amplification / DoS via unknown issuers                                  | Unknown `iss` is rejected *before* any network call; JWKS results (including failures) are cached                                                                                           |
| Replay of a stolen subject token                                                        | Not solved by this design, and not solvable without introspection at the IdP — the subject token is a bearer credential and this feature does not make it worse. Note it in operator docs.  |
| Silent privilege drift as Keycloak groups change                                        | Groups are recomputed on every exchange; short access-token lifetimes are the enforcement mechanism                                                                                         |
| The exchange path computing authorizations differently from `/authorize`                | All three grant paths share `userAuthorization` (`scope_pipeline.go`); the authorization-code and device-code flows were refactored onto it rather than the exchange path reimplementing it |
| Exchanged tokens carrying admin authority                                               | By construction: the issuer only mints `storage.*`, `collection.*`, `pelican.transfer`, and protocol scopes. `server.admin` and the `web_ui` scopes are not reachable from any grant path   |
| Rate abuse of the exchange endpoint                                                     | Apply per-client and per-IP limiting, reusing the token-bucket in `oauth2/issuer/rate_limit.go`                                                                                             |

Every exchange should emit one audit log line: client ID, external issuer, external subject, resolved local user, matched groups, granted scopes, and outcome.

## 13. Testing

- **Unit** (`oauth2/issuer/`): issuer resolution, `alg`/`aud`/`scope`/claim policy enforcement, group filtering and prefixing, lifetime capping, client-blessing gating, `act` claim contents. Config parsing/validation via `ParseExternalIssuers`.
- **Security regression** (`oauth2/issuer/security_regression_test.go` is the established home): unknown issuer rejected before any HTTP call; disabled issuer rejected; unblessed client rejected; `none`/HS256 rejected; audience-less token rejected; external groups never yielding `server.admin`; expired subject token rejected.
- **Integration** (`oauth2/issuer/integration_test.go`): a stub external IdP — an `httptest` server publishing `/.well-known/openid-configuration` and a JWKS, signing tokens with a generated key (`server_utils/oidc_test.go` and `cmd/sample_metadata_server` both have usable prior art) — driving a full exchange and asserting the resulting WLCG token's scopes against configured `Issuer.AuthorizationTemplates`.
- **DB** (`database/`): migration up/down for the `allow_external_exchange` client column.
- **E2E** (`e2e_fed_tests/`): stub IdP → exchange → real object `GET` through an origin, proving the minted token is accepted by the data plane.
- **Frontend**: `tsc` type-checks the read-only issuer panel and the identity link/adopt form.

## 14. Phasing

1. **Phase 0 — done.** Identity unification (§6.3), which subsumes the hand-written cross-table checks entirely. The other prerequisite, globally-unique usernames (§6.2), comes from PR #3618, which this branch is based on.
1. **Phase 1 — done.** Migration and model; external verification path dispatched from `handleTokenExchange`; JWKS cache; identity lookup with `AutoEnroll`; `GroupMode` `ignore`/`claim` with prefixing; shared scope pipeline; admin REST including `probe` and `dry-run`; CLI; kill-switch parameter; swagger.
1. **Phase 2 — done.** Web UI: the read-only external-issuer panel, the client-blessing toggle, probe/dry-run dialogs, and the identity link/adopt form (§10.3).
1. **Phase 3 — done, except two items deliberately not built.** `AdoptUserIdentity` is exposed through REST (`POST /users/{id}/identities/adopt`), CLI (`pelican-server user identity adopt`), and the UI; `GroupMode: mapped` ships with its mapping table and surfaces. **Not built:** IdP introspection for opaque subject tokens, which nothing needs — Keycloak issues JWTs — and which would be speculative surface area. (Config-authoritative issuers, once a "phase-2 maybe", are now the shipped model — see §11.)

Phases 1 and 2 together are what the collaboration needs. Phase 1 alone is enough to integrate against, since every surface it adds is reachable from the CLI.

### Files

| Area                                     | File                                                                                   |
| ---------------------------------------- | -------------------------------------------------------------------------------------- |
| Schema                                   | `database/origin_migrations/20260824120000_add_client_external_exchange.sql`           |
| Model                                    | `oauth2/issuer/models.go` (`ExternalIssuerRecord`, `OIDCClientRecord.ExchangeIssuers`) |
| Config surface, validation, storage CRUD | `oauth2/issuer/external_issuer.go`                                                     |
| JWKS cache and token verification        | `oauth2/issuer/external_verify.go`                                                     |
| Identity and group mapping               | `oauth2/issuer/external_identity.go`                                                   |
| Exchange decision and minting            | `oauth2/issuer/external_exchange.go`                                                   |
| Shared scope pipeline                    | `oauth2/issuer/scope_pipeline.go`                                                      |
| Admin REST handlers                      | `oauth2/issuer/external_admin_handlers.go`                                             |
| CLI                                      | `cmd/origin_external_issuer.go`, `cmd/origin_client.go`                                |
| Tests                                    | `oauth2/issuer/external_exchange_test.go`, `database/users_test.go`                    |

## 15. Decisions needing sign-off

Settled during implementation:

1. **`AutoEnroll` defaults to true** (§6.1), on the basis that PR #3618 lands the global-username constraint first.
1. **Group prefixing defaults to `<Name>:`**, per-issuer configurable, with `AllowFlatGroups` as the opt-out (§7).
1. **Refresh tokens are off by default**, per-issuer opt-in (§9).
1. **External issuers are per-namespace**, matching `oidc_clients` (§4.1).
1. **Policy is DB-only**; the only new config parameter is a kill switch (§11).
1. **A specific requested `audience` is not honored on the external path** (§9).

Still open:

1. **Whether config-file seeding of trusted issuers is wanted** for GitOps-style deployments (§11 argues against it; not built).
1. Whether the all-or-none client blessing is granular enough, or whether some deployments will want per-issuer client scoping. All-or-none was chosen for simplicity (the operations team's request); per-issuer would return if a concrete need appears.
