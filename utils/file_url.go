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

package utils

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
)

// The cache writes file:// URLs (a shared-filesystem tiering target's
// redirects) and the client reads them.  Both directions live here so the
// two sides cannot drift into different spellings of the same path -- a
// mismatch would not fail to compile, it would make every redirect miss.

// FileURLToPath returns the local path a file URL names (RFC 8089).  On
// Windows the URL path of a drive-letter path carries a leading slash --
// file:///C:/data/obj -- which is dropped before converting separators.
//
// URL.Path is already percent-decoded; it must not be decoded again, or a
// file named "a%41" would turn into "aA".
func FileURLToPath(u *url.URL) string {
	p := u.Path
	if runtime.GOOS == "windows" {
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
	}
	return filepath.FromSlash(p)
}

// PathToFileURL is the inverse of FileURLToPath for an absolute local path.
// The URL has no host, which RFC 8089 reads as "this machine".
func PathToFileURL(path string) *url.URL {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a Windows drive-letter path
	}
	return &url.URL{Scheme: "file", Path: p}
}
