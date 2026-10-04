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

package local_cache

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

// testInstanceHash returns a distinct, valid instance hash for n: n in hex,
// zero-padded to 64 digits.  Hashes sort in the order of n.
func testInstanceHash(n int) InstanceHash {
	return mustInstanceHash(fmt.Sprintf("%064x", n))
}

// namedInstanceHash returns a valid instance hash derived from name, for
// tests that want a memorable, distinct hash per case.
func namedInstanceHash(name string) InstanceHash {
	return InstanceHashFromSHA256(sha256.Sum256([]byte(name)))
}

// randomInstanceHash returns a random valid instance hash.
//
// It must actually be random: table-driven tests call it once per subtest
// against a shared store, and a deterministic hash would have each subtest
// silently overwrite its predecessor.
func randomInstanceHash(t *testing.T) InstanceHash {
	t.Helper()
	var digest [sha256.Size]byte
	_, err := rand.Read(digest[:])
	require.NoError(t, err)
	return InstanceHashFromSHA256(digest)
}

// mustInstanceHash parses a literal hash, panicking if it is malformed.
func mustInstanceHash(s string) InstanceHash {
	h, err := ParseInstanceHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

// TestInstanceHashEncoding: the struct must look exactly like the string it
// replaced everywhere the hash leaves the process -- printed, in database
// keys, and serialized.
func TestInstanceHashEncoding(t *testing.T) {
	hexText := strings.Repeat("0123456789abcdef", 4)
	h := mustInstanceHash(hexText)

	assert.Equal(t, hexText, h.String())
	assert.Equal(t, hexText, fmt.Sprintf("%s", h))
	assert.Equal(t, hexText, fmt.Sprintf("%v", h))
	assert.Equal(t, "m:"+hexText, string(MetaKey(h)))
	assert.Equal(t, "01/23/"+hexText[4:], GetInstanceStoragePath(h))

	js, err := json.Marshal(map[string]InstanceHash{"h": h})
	require.NoError(t, err)
	assert.JSONEq(t, `{"h":"`+hexText+`"}`, string(js))
	var back map[string]InstanceHash
	require.NoError(t, json.Unmarshal(js, &back))
	assert.Equal(t, h, back["h"])
	assert.Error(t, json.Unmarshal([]byte(`{"h":"../etc"}`), &back), "decoding must validate")

	assert.True(t, InstanceHash{}.IsZero())
	assert.False(t, h.IsZero())
}

// TestInstanceHashCompareIsKeyOrder: the tiering sweep and the consistency
// checker merge-join database keys against listings by hash, so Compare must
// agree with the byte order of the keys the hashes produce.
func TestInstanceHashCompareIsKeyOrder(t *testing.T) {
	hashes := []InstanceHash{{}}
	for i := 0; i < 64; i++ {
		hashes = append(hashes, randomInstanceHash(t))
	}
	byCompare := append([]InstanceHash(nil), hashes...)
	sort.Slice(byCompare, func(i, j int) bool { return byCompare[i].Compare(byCompare[j]) < 0 })
	byKey := append([]InstanceHash(nil), hashes...)
	sort.Slice(byKey, func(i, j int) bool { return string(MetaKey(byKey[i])) < string(MetaKey(byKey[j])) })
	assert.Equal(t, byKey, byCompare)
	assert.True(t, byCompare[0].IsZero(), "the zero value sorts first, so it is a valid start cursor")
}

// TestInstanceHashFromKey: a hash read back out of a database key is
// validated like any other.
func TestInstanceHashFromKey(t *testing.T) {
	h := namedInstanceHash("from-key")
	got, err := InstanceHashFromKey(TierUploadIntentKey(h), PrefixTierUpload)
	require.NoError(t, err)
	assert.Equal(t, h, got)

	_, err = InstanceHashFromKey(MetaKey(h), PrefixTierUpload)
	assert.Error(t, err, "wrong prefix")
	_, err = InstanceHashFromKey([]byte(PrefixMeta+"../../etc/passwd"), PrefixMeta)
	assert.Error(t, err, "not a hash")
	_, err = InstanceHashFromKey([]byte(PrefixMeta), PrefixMeta)
	assert.Error(t, err, "empty")
}

// TestComputeInstanceHashIsUnchanged pins the derivation: the struct type must
// produce exactly the hex text the string type did, or every existing cache
// would orphan its contents.  The expected values are computed here the way
// the string-typed code did it.
func TestComputeInstanceHashIsUnchanged(t *testing.T) {
	salt := []byte("golden-salt")
	url := "pelican://Example.ORG/ns/Data.txt"

	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(normalizeURL(url)))
	wantObject := hex.EncodeToString(mac.Sum(nil))

	mac = hmac.New(sha256.New, salt)
	mac.Write([]byte("etag-1:" + wantObject))
	wantInstance := hex.EncodeToString(mac.Sum(nil))

	objectHash := ComputeObjectHash(salt, url)
	assert.Equal(t, wantObject, objectHash.String())
	assert.Equal(t, wantInstance, ComputeInstanceHash(salt, "etag-1", objectHash).String())
	assert.Equal(t, "e:"+wantObject, string(ETagKey(objectHash)))
}

// TestHashesSerializeAsStrings: a hash field serializes byte for byte as the
// string field it replaced, in msgpack (the database's value encoding) and
// JSON, so a record written with either type reads back with the other.
func TestHashesSerializeAsStrings(t *testing.T) {
	type asString struct {
		H string `msgpack:"h" json:"h"`
	}
	type asInstance struct {
		H InstanceHash `msgpack:"h" json:"h"`
	}
	type asObject struct {
		H ObjectHash `msgpack:"h" json:"h"`
	}
	inst := namedInstanceHash("serialize")
	obj := ComputeObjectHash([]byte("salt"), "pelican://example.org/ns/obj")

	for _, tc := range []struct {
		name  string
		hex   string
		typed any
		back  func() (any, any)
	}{
		{"instance", inst.String(), asInstance{inst}, func() (any, any) { return &asInstance{}, asInstance{inst} }},
		{"object", obj.String(), asObject{obj}, func() (any, any) { return &asObject{}, asObject{obj} }},
		{"zero", "", asInstance{}, func() (any, any) { return &asInstance{}, asInstance{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, codec := range []struct {
				name      string
				marshal   func(any) ([]byte, error)
				unmarshal func([]byte, any) error
			}{
				{"msgpack", msgpack.Marshal, msgpack.Unmarshal},
				{"json", json.Marshal, json.Unmarshal},
			} {
				typedBytes, err := codec.marshal(tc.typed)
				require.NoError(t, err)
				stringBytes, err := codec.marshal(asString{tc.hex})
				require.NoError(t, err)
				assert.Equal(t, stringBytes, typedBytes, "%s: same bytes as a string field", codec.name)

				// Written as a string, read as the hash type.
				out, want := tc.back()
				require.NoError(t, codec.unmarshal(stringBytes, out), codec.name)
				assert.Equal(t, want, reflect.ValueOf(out).Elem().Interface(), codec.name)
			}
		})
	}

	// Decoding validates: a string field holding something else is refused
	// rather than becoming a hash.
	bad, err := msgpack.Marshal(asString{"../../etc/passwd"})
	require.NoError(t, err)
	assert.Error(t, msgpack.Unmarshal(bad, &asInstance{}))
	assert.Error(t, msgpack.Unmarshal(bad, &asObject{}))
	// A nil (absent) value is the zero hash.
	nilBytes, err := msgpack.Marshal(struct {
		H *string `msgpack:"h"`
	}{})
	require.NoError(t, err)
	var fromNil asInstance
	require.NoError(t, msgpack.Unmarshal(nilBytes, &fromNil))
	assert.True(t, fromNil.H.IsZero())
}

// TestHashDerivationGolden pins the derivation to literal values, so a
// change to it -- which would orphan every existing cache's contents -- cannot
// pass by changing the code and its test together.
func TestHashDerivationGolden(t *testing.T) {
	salt := []byte("golden-salt")
	objectHash := ComputeObjectHash(salt, "pelican://Example.ORG/ns/Data.txt")
	assert.Equal(t, goldenObjectHash, objectHash.String())
	assert.Equal(t, goldenInstanceHash, ComputeInstanceHash(salt, "etag-1", objectHash).String())
}

// The golden values were computed independently of this code, with Python's
// hmac module: HMAC-SHA256("golden-salt", "pelican://example.org/ns/Data.txt")
// and HMAC-SHA256("golden-salt", "etag-1:" + that hex).
const (
	goldenObjectHash   = "306535521852b5816fd3023dc4284906d08853600fa79d0bbb21d8e7a308a6c0"
	goldenInstanceHash = "12332910749beb2a9aeeec60c68ac5dad210e161b8c0845c5c25e3aaa713c303"
)
