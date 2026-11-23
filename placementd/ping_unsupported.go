//go:build windows

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

// CEDAR needs SCM_RIGHTS and the rest of the Unix socket facilities, so it
// does not build for Windows. The origin does not run there either, but
// origin_serve does have to compile, which is what this file is for: the rest
// of the package stays portable and NewVerifier refuses a configured placement
// daemon outright rather than accepting it and then failing every token.

import (
	"context"

	"github.com/pkg/errors"
)

// cedarAvailable reports that this platform cannot talk CEDAR.
const cedarAvailable = false

// defaultPing is never reached: NewVerifier refuses to build a verifier when
// cedarAvailable is false.
var defaultPing = func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
	return "", errors.Wrap(ErrUnavailable, "CEDAR is not supported on this platform")
}
