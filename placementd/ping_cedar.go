//go:build !windows

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

package placementd

// The CEDAR half of `condor_ping`. Confined to this file because CEDAR relies
// on SCM_RIGHTS and other Unix socket facilities and does not build on
// Windows, while the rest of this package — recognition, caching, rate
// limiting — is portable and compiles (and is tested) everywhere Pelican does.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
)

// cedarAvailable reports that this platform can talk CEDAR.
const cedarAvailable = true

// defaultPing is what a Verifier uses unless a test replaces it.
var defaultPing = cedarPing

// cedarPing asks the placement daemon who a token belongs to, offering the
// caller's token as the only credential, and returns the identity the daemon
// reported. Failures come back carrying ErrRefused or ErrUnavailable.
func cedarPing(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
	// Everything about this config is deliberate:
	//
	//   - Token carries the caller's credential and TokenFile/TokenDir are
	//     left empty, so CEDAR has nothing else to fall back to. If this
	//     origin ever holds HTCondor credentials of its own, a token the
	//     daemon refuses must fail — not quietly succeed as the origin's own
	//     identity and hand the caller whatever that identity may do.
	//   - IDTOKENS is the only method offered, for the same reason.
	//   - Authentication is REQUIRED, so an anonymous session is a failure
	//     rather than a handshake that reports no identity.
	//   - Encryption is REQUIRED because a bearer token is on the wire.
	//   - SecurityTag partitions the client session cache by token. Sessions
	//     are keyed by peer and command; two tokens sharing an entry would
	//     mean the second one resuming a session the first authenticated,
	//     and being reported as the first one's identity.
	digest := sha256.Sum256([]byte(tokenStr))
	secConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthIDTokens},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		Token:          tokenStr,
		TrustDomain:    trustDomain,
		PeerName:       address,
		SecurityTag:    "pelican-placementd:" + hex.EncodeToString(digest[:]),
		Command:        int(commands.DC_NOP),
		Subsystem:      "TOOL",
	}

	// DC_NOP is registered by HTCondor's daemon core at ALLOW, so it runs
	// for any identity the daemon can authenticate and its handler reads
	// nothing: the handshake is the whole exchange, and the connection can
	// be closed as soon as it has been read.
	conn, err := client.ConnectAndAuthenticate(ctx, address, secConfig)
	if err != nil {
		return "", classifyPingError(err)
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("Failed to close the placement-daemon connection: %v", cerr)
		}
	}()

	negotiation := conn.GetSecurityNegotiation()
	if negotiation == nil {
		return "", errors.Wrap(ErrUnavailable, "the placement daemon completed no security negotiation")
	}
	if !negotiation.Authentication {
		return "", errors.Wrap(ErrRefused, "the placement daemon did not authenticate the connection")
	}
	return negotiation.User, nil
}

// classifyPingError sorts a CEDAR failure into "the token is bad" and "we
// could not find out", which is the distinction the caching and the operator's
// logs both turn on.
func classifyPingError(err error) error {
	// A deadline or a cancellation says nothing about the token, however
	// deep in the error chain it sits — a handshake that timed out is
	// reported as every method having failed, so this has to be checked
	// before the authentication failure below.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return errors.Wrap(ErrUnavailable, err.Error())
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return errors.Wrap(ErrUnavailable, err.Error())
	}

	// The daemon ran the handshake and would not accept the credential.
	var exhausted *security.AuthMethodsExhaustedError
	if errors.As(err, &exhausted) {
		return errors.Wrap(ErrRefused, err.Error())
	}
	// The daemon knows who we are and will not let that identity run
	// DC_NOP. That is its policy talking, not a transport problem, and no
	// identity we could authorize comes out of it.
	var denied *security.AuthorizationError
	if errors.As(err, &denied) {
		return errors.Wrap(ErrRefused, err.Error())
	}

	return errors.Wrap(ErrUnavailable, err.Error())
}
