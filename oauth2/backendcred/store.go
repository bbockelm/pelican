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
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/config"
)

// RegistrationMethod records how a credential's OAuth client came to exist.
type RegistrationMethod string

const (
	// The administrator configured a client ID (and possibly a secret).
	RegistrationPreconfigured RegistrationMethod = "preconfigured"
	// The client_id is the URL of a client ID metadata document hosted by the
	// federation's director.
	RegistrationCIMD RegistrationMethod = "cimd"
	// The client was registered with the issuer's registration_endpoint
	// (RFC 7591).
	RegistrationDCR RegistrationMethod = "dcr"
)

// Record is the durable state of one backend credential: the OAuth client it
// was issued to and the refresh token that keeps it alive.
type Record struct {
	ID                      string
	Issuer                  string
	Method                  RegistrationMethod
	ClientID                string
	ClientSecret            string
	RegistrationAccessToken string
	RegistrationClientURI   string
	// ClientSecretExpiresAt is when a dynamically registered client's
	// secret expires (zero: never).
	ClientSecretExpiresAt time.Time
	RefreshToken          string
	Scopes                []string
	ActivatedBy           string
	ActivatedAt           time.Time
}

// Store persists Records.  Load returns (nil, nil) when there is none.
type Store interface {
	Load(ctx context.Context, id string) (*Record, error)
	Save(ctx context.Context, rec *Record) error
	Delete(ctx context.Context, id string) error
}

// credentialRow is the database form of a Record.  The secret columns hold
// config.EncryptString output -- sealed with a key derived from the server's
// issuer key, as the Globus backend stores its refresh tokens -- so a copy of
// the database alone does not leak usable credentials.
type credentialRow struct {
	ID                      string `gorm:"primaryKey"`
	Issuer                  string `gorm:"not null;default:''"`
	RegistrationMethod      string `gorm:"not null;default:''"`
	ClientID                string `gorm:"not null;default:''"`
	ClientSecret            string `gorm:"not null;default:''"`
	RegistrationAccessToken string `gorm:"not null;default:''"`
	RegistrationClientURI   string `gorm:"not null;default:''"`
	ClientSecretExpiresAt   *time.Time
	RefreshToken            string `gorm:"not null;default:''"`
	Scopes                  string `gorm:"not null;default:''"`
	ActivatedBy             string `gorm:"not null;default:''"`
	ActivatedAt             time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

func (credentialRow) TableName() string { return "backend_oauth_credentials" }

// dbStore keeps Records in the server database.
type dbStore struct {
	db *gorm.DB
}

// NewDBStore returns a Store backed by the backend_oauth_credentials table.
func NewDBStore(db *gorm.DB) Store {
	return &dbStore{db: db}
}

func encryptIfSet(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return config.EncryptString(value)
}

func (s *dbStore) Load(ctx context.Context, id string) (*Record, error) {
	var row credentialRow
	err := s.db.WithContext(ctx).Where("id = ?", id).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load backend credential %s", id)
	}

	rec := &Record{
		ID:                    row.ID,
		Issuer:                row.Issuer,
		Method:                RegistrationMethod(row.RegistrationMethod),
		ClientID:              row.ClientID,
		RegistrationClientURI: row.RegistrationClientURI,
		ActivatedBy:           row.ActivatedBy,
		ActivatedAt:           row.ActivatedAt,
	}
	if row.Scopes != "" {
		rec.Scopes = strings.Split(row.Scopes, " ")
	}
	if row.ClientSecretExpiresAt != nil {
		rec.ClientSecretExpiresAt = *row.ClientSecretExpiresAt
	}
	rotated := map[string]any{}
	for _, field := range []struct {
		column string
		sealed string
		out    *string
	}{
		{"client_secret", row.ClientSecret, &rec.ClientSecret},
		{"registration_access_token", row.RegistrationAccessToken, &rec.RegistrationAccessToken},
		{"refresh_token", row.RefreshToken, &rec.RefreshToken},
	} {
		if field.sealed == "" {
			continue
		}
		plain, reEncrypted, err := config.DecryptStringAndRotate(field.sealed)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decrypt the %s of backend credential %s", strings.ReplaceAll(field.column, "_", " "), id)
		}
		*field.out = plain
		if reEncrypted != "" {
			rotated[field.column] = reEncrypted
		}
	}
	if len(rotated) > 0 {
		if err := s.db.WithContext(ctx).Model(&credentialRow{}).Where("id = ?", id).Updates(rotated).Error; err != nil {
			log.Warningf("Failed to re-encrypt backend credential %s under the current issuer key: %v", id, err)
		}
	}
	return rec, nil
}

func (s *dbStore) Save(ctx context.Context, rec *Record) error {
	row := credentialRow{
		ID:                    rec.ID,
		Issuer:                rec.Issuer,
		RegistrationMethod:    string(rec.Method),
		ClientID:              rec.ClientID,
		RegistrationClientURI: rec.RegistrationClientURI,
		Scopes:                strings.Join(rec.Scopes, " "),
		ActivatedBy:           rec.ActivatedBy,
		ActivatedAt:           rec.ActivatedAt,
	}
	if !rec.ClientSecretExpiresAt.IsZero() {
		exp := rec.ClientSecretExpiresAt
		row.ClientSecretExpiresAt = &exp
	}
	var err error
	if row.ClientSecret, err = encryptIfSet(rec.ClientSecret); err != nil {
		return errors.Wrap(err, "failed to encrypt the client secret")
	}
	if row.RegistrationAccessToken, err = encryptIfSet(rec.RegistrationAccessToken); err != nil {
		return errors.Wrap(err, "failed to encrypt the registration access token")
	}
	if row.RefreshToken, err = encryptIfSet(rec.RefreshToken); err != nil {
		return errors.Wrap(err, "failed to encrypt the refresh token")
	}
	// Upsert every mutable column, so clearing a field (a revoked refresh
	// token) really clears it, while created_at keeps the first activation.
	upsert := clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"issuer", "registration_method", "client_id", "client_secret",
			"registration_access_token", "registration_client_uri", "client_secret_expires_at", "refresh_token",
			"scopes", "activated_by", "activated_at", "updated_at",
		}),
	}
	if err := s.db.WithContext(ctx).Clauses(upsert).Create(&row).Error; err != nil {
		return errors.Wrapf(err, "failed to save backend credential %s", rec.ID)
	}
	return nil
}

func (s *dbStore) Delete(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Where("id = ?", id).Delete(&credentialRow{}).Error; err != nil {
		return errors.Wrapf(err, "failed to delete backend credential %s", id)
	}
	return nil
}
