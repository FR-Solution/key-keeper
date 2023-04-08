#!/usr/bin/env bash

# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION=$(git describe --abbrev=0 --tag)

TOOLS_ROOT="$GOPATH/src/$PROJECT"
OUTPUTDIR=$TOOLS_ROOT/_output/releases
mkdir -p "$OUTPUTDIR"

GO_LDFLAGS="-X ${PROJECT}/pkg/version.Version=${VERSION}"

os="linux"
arch=$(basename "linux/amd64")

KEY_KEEPER_BIN="key-keeper"

output_bin=${TOOLS_ROOT}/_output/bin/$arch-$os/${KEY_KEEPER_BIN}

GOARCH="$arch" GOOS="$os" CGO_ENABLED=0  go build \
-o ${output_bin} \
-ldflags "${GO_LDFLAGS}" \
cmd/key-keeper/main.go

file ${output_bin}
tar zcf "$OUTPUTDIR/key-keeper-$VERSION-$os-$arch.tar.gz" \
-C ${TOOLS_ROOT}/_output/bin/$arch-$os \
${KEY_KEEPER_BIN}


printf "\n## Downloads\n\n" | tee -a release-notes.md
echo "| file | sha256 | sha512" | tee -a release-notes.md
echo "| ---- | ------ | ------" | tee -a release-notes.md

for file in "$OUTPUTDIR"/*.tar.gz; do
    SHA256=$(shasum -a 256 "$file" | sed -e "s,$file,," | awk '{print $1}' | tee "$file.sha256")
    SHA512=$(shasum -a 512 "$file" | sed -e "s,$file,," | awk '{print $1}' | tee "$file.sha512")
    BASE=$(basename "$file")
    echo "| $BASE | $SHA256 | $SHA512 |" | tee -a release-notes.md
done
