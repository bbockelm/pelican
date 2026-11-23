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

import (
	"context"
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/bbockelm/cedar/security"
)

// TestClassifyPingError pins the distinction the caching turns on: a refusal
// is the token's fault and is remembered, an unreachable daemon is not.
func TestClassifyPingError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"authentication exhausted", &security.AuthMethodsExhaustedError{}, ErrRefused},
		{"command denied", &security.AuthorizationError{ReturnCode: "DENIED"}, ErrRefused},
		{"dial failure", &net.OpError{Op: "dial", Err: errors.New("refused")}, ErrUnavailable},
		{"deadline", context.DeadlineExceeded, ErrUnavailable},
		{"cancelled", context.Canceled, ErrUnavailable},
		{"anything else", errors.New("some other failure"), ErrUnavailable},
		{
			// A handshake that timed out is reported as every method
			// having failed; the timeout is the real story and must not
			// be cached as a refusal of a token that may be perfectly
			// good.
			name: "timeout inside an exhausted handshake",
			err: &security.AuthMethodsExhaustedError{Attempts: []security.AuthMethodAttempt{
				{Method: security.AuthIDTokens, Err: context.DeadlineExceeded},
			}},
			want: ErrUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, classifyPingError(tc.err), tc.want)
		})
	}
}

// TestCedarPingRefusesAnUnreachableDaemon checks the one thing a real
// handshake cannot be stood in for: that the production ping classifies its
// own failures, since the portable core trusts it to.
func TestCedarPingRefusesAnUnreachableDaemon(t *testing.T) {
	// Port 1 on the loopback: nothing listens, and the failure is a dial
	// error rather than anything about the token.
	_, err := cedarPing(context.Background(), "127.0.0.1:1", testTrustDomain, "not.a.real.token")
	assert.ErrorIs(t, err, ErrUnavailable)
}
