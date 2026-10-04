#!/bin/bash
# Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You may
# obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Installs the Versity S3 Gateway (versitygw), the S3 server the S3-backed
# tests run against (see test_utils/s3server.go), into the directory given as
# the only argument.  Put that directory on PATH to run those tests; with
# TEST_REQUIRE_S3_SERVER set, they fail rather than skip when it is missing.
#
# The release tarball is checked against a SHA-256 pinned here, not against
# the release's own checksums.txt, which would come from the same place as
# the tarball.  To upgrade, change VERSITYGW_VERSION and copy the tarball
# lines for the platforms below from that release's checksums.txt.

set -euo pipefail

VERSITYGW_VERSION=1.8.0

if [ $# -ne 1 ]; then
  echo "usage: $0 <install-dir>" >&2
  exit 2
fi
dest=$1

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    platform=Linux_x86_64
    sha256=2ba2c734d10d2c4e651d03182cb4b246656bc735a2f282db7b0b73fba6073467 ;;
  Linux/aarch64 | Linux/arm64)
    platform=Linux_arm64
    sha256=b34051d33f5a9c457f790896acb7bd7d7e15ad8d92efb70616b924f37e401910 ;;
  Darwin/arm64)
    platform=Darwin_arm64
    sha256=4953096f65a9c0d62ab184fb6b2ba7c2435229205cf00a56cb62cd4bf6b216ca ;;
  Darwin/x86_64)
    platform=Darwin_x86_64
    sha256=104bd978e80ef0173554cfd8630ccc5bac24b00da440510b60365a3b6b6ab134 ;;
  *)
    echo "no pinned versitygw release for $(uname -s)/$(uname -m)" >&2
    exit 1 ;;
esac

name="versitygw_v${VERSITYGW_VERSION}_${platform}"
url="https://github.com/versity/versitygw/releases/download/v${VERSITYGW_VERSION}/${name}.tar.gz"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL --retry 3 --retry-all-errors -o "$work/$name.tar.gz" "$url"

if command -v sha256sum >/dev/null; then
  sha256sum_cmd=(sha256sum)
else
  sha256sum_cmd=(shasum -a 256)
fi
echo "$sha256  $work/$name.tar.gz" | "${sha256sum_cmd[@]}" -c -

tar -xzf "$work/$name.tar.gz" -C "$work"
mkdir -p "$dest"
install -m 0755 "$work/$name/versitygw" "$dest/versitygw"
"$dest/versitygw" --version
