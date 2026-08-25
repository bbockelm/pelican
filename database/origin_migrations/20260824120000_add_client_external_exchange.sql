-- +goose Up
-- +goose StatementBegin

-- Bless an OAuth2 client to exchange tokens from trusted external issuers.
--
-- Trusted external issuers themselves are defined in configuration
-- (Origin.Exports[*].ExternalIssuers / Issuer.ExternalIssuers), not the
-- database — they are trust anchors and belong under change control. What stays
-- in the database is the per-client blessing, because clients are created at
-- runtime (dynamic registration, admin API). The flag is all-or-none: a blessed
-- client may exchange tokens from any configured external issuer in its
-- namespace; the default (false) means it may exchange only tokens this server
-- issued.
ALTER TABLE oidc_clients ADD COLUMN allow_external_exchange INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE oidc_clients DROP COLUMN allow_external_exchange;

-- +goose StatementEnd
