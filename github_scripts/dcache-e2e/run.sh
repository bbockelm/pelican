#!/bin/bash
#
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
# Starts a single-node dCache and runs Pelican's dCache tiering checks
# against it.  Usage: run.sh <work directory>
set -euo pipefail
work=${1:?usage: run.sh <work directory>}
mkdir -p "$work/logs"
docker version | tee "$work/logs/docker-version.txt"
