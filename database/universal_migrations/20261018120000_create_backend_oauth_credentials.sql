-- +goose Up
-- +goose StatementBegin
-- Long-lived OAuth credentials a server holds for its storage backends
-- (WebDAV/HTTPS origins, cache tiering targets), acquired with the device
-- authorization grant.  The secret columns hold config.EncryptString output.
CREATE TABLE IF NOT EXISTS backend_oauth_credentials (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL DEFAULT '',
    registration_method TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL DEFAULT '',
    registration_access_token TEXT NOT NULL DEFAULT '',
    registration_client_uri TEXT NOT NULL DEFAULT '',
    client_secret_expires_at DATETIME,
    refresh_token TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT '',
    activated_by TEXT NOT NULL DEFAULT '',
    activated_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backend_oauth_credentials;
-- +goose StatementEnd
