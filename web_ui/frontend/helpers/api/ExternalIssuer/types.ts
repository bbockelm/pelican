/**
 * Trusted external issuers: foreign OAuth2/OIDC providers whose access tokens
 * the origin's embedded issuer will exchange (RFC 8693) for Pelican tokens.
 *
 * Field names are snake_case because they mirror the wire format of the issuer
 * admin API, which follows OAuth2 naming (`client_id`, `grant_types`, …) rather
 * than the camelCase used by the user/group APIs. Matching the wire exactly
 * avoids a translation layer that could silently drop a field.
 *
 * See ExternalIssuerDetail in oauth2/issuer/external_issuer.go. The exchanged
 * token's authorizations always come from the mapped local user's own rules;
 * the external token's scopes are a precondition for accepting it, never a
 * source of authority.
 */

export type GroupMode = 'ignore' | 'claim' | 'mapped';

export interface ExternalIssuer {
  name: string;
  issuer_url: string;
  jwks_url?: string;
  enabled: boolean;

  required_audiences: string[];
  /** Acknowledgment that tokens minted for ANY audience are accepted. */
  allow_any_audience: boolean;
  required_scopes: string[];
  required_claims: Record<string, string>;
  allowed_algorithms: string[];

  subject_claim: string;
  username_claims: string[];
  auto_enroll: boolean;

  group_claim: string;
  group_mode: GroupMode;
  group_prefix: string;
  /** Acknowledgment that foreign group names are used unprefixed. */
  allow_flat_groups: boolean;
  group_allow_patterns: string[];
  include_local_groups: boolean;

  group_mappings?: Record<string, string>;
  allow_refresh: boolean;
  max_token_lifetime_seconds: number;
}

/** Create or partial-update body. Omitted fields keep their stored value. */
export type ExternalIssuerPost = Partial<
  Omit<ExternalIssuer, 'id' | 'created_at' | 'updated_at'>
>;

export interface ExternalIssuerProbe {
  ok: boolean;
  issuer_url: string;
  jwks_url?: string;
  key_count: number;
  key_ids?: string[];
  algorithms?: string[];
  error?: string;
}

export interface ExternalIssuerDryRun {
  ok: boolean;
  error?: string;
  external_issuer?: string;
  external_subject?: string;
  username?: string;
  user_id?: string;
  /** True when no account is linked yet and one would be created. */
  would_enroll: boolean;
  groups?: string[];
  /** The groups that actually drove an authorization. */
  matched_groups?: string[];
  granted_scopes?: string[];
  lifetime_seconds?: number;
}

/**
 * An OAuth2 client registered with the embedded issuer, as the admin API
 * returns it. Only the fields the blessing flow needs are modelled.
 *
 * `allow_external_token_exchange` blesses the client to exchange tokens from the
 * namespace's configured external issuers (all-or-none).
 */
export interface IssuerClient {
  client_id: string;
  grant_types: string[];
  scopes: string[];
  allow_external_token_exchange: boolean;
  created_at: string;
}

export const TOKEN_EXCHANGE_GRANT =
  'urn:ietf:params:oauth:grant-type:token-exchange';
