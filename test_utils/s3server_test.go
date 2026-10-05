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

package test_utils

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/blobstore"
)

// TestS3ServerCapabilities pins down the S3 behavior the S3-backed suites
// rely on, against the server StartS3Server runs.  Those suites would mostly
// notice a missing capability too, but some only by skipping or by failing
// somewhere far from the cause; this says directly what the server must do,
// so replacing or upgrading it shows at once what it lacks.
func TestS3ServerCapabilities(t *testing.T) {
	srv := StartS3Server(t, "capabilities")
	client := srv.Client()
	ctx := context.Background()

	put := func(t *testing.T, key, body string) *s3.PutObjectOutput {
		t.Helper()
		out, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &srv.Bucket, Key: aws.String(key), Body: strings.NewReader(body),
		})
		require.NoError(t, err)
		return out
	}
	get := func(t *testing.T, in *s3.GetObjectInput) (string, error) {
		t.Helper()
		in.Bucket = &srv.Bucket
		out, err := client.GetObject(ctx, in)
		if err != nil {
			return "", err
		}
		defer out.Body.Close()
		data, err := io.ReadAll(out.Body)
		require.NoError(t, err)
		return string(data), nil
	}
	httpGet := func(t *testing.T, rawURL string) (int, string) {
		t.Helper()
		resp, err := http.Get(rawURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(data)
	}
	presign := func(t *testing.T, in *s3.GetObjectInput) string {
		t.Helper()
		in.Bucket = &srv.Bucket
		req, err := s3.NewPresignClient(client).PresignGetObject(ctx, in, s3.WithPresignExpires(time.Minute))
		require.NoError(t, err)
		return req.URL
	}

	t.Run("HeaderSignedRoundTripAndETag", func(t *testing.T) {
		out := put(t, "plain", "hello")
		require.NotNil(t, out.ETag)
		head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &srv.Bucket, Key: aws.String("plain")})
		require.NoError(t, err)
		assert.Equal(t, *out.ETag, aws.ToString(head.ETag))
		assert.Equal(t, int64(5), aws.ToInt64(head.ContentLength))
		got, err := get(t, &s3.GetObjectInput{Key: aws.String("plain")})
		require.NoError(t, err)
		assert.Equal(t, "hello", got)
	})

	t.Run("RangeRead", func(t *testing.T) {
		put(t, "ranged", "0123456789")
		got, err := get(t, &s3.GetObjectInput{Key: aws.String("ranged"), Range: aws.String("bytes=3-")})
		require.NoError(t, err)
		assert.Equal(t, "3456789", got)
	})

	t.Run("NotFoundShapes", func(t *testing.T) {
		_, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &srv.Bucket, Key: aws.String("missing")})
		assert.True(t, blobstore.IsNotFound(err), "HEAD of a missing key: %v", err)
		_, err = get(t, &s3.GetObjectInput{Key: aws.String("missing")})
		assert.True(t, blobstore.IsNotFound(err), "GET of a missing key: %v", err)
	})

	t.Run("IfMatch", func(t *testing.T) {
		out := put(t, "conditional", "v1")
		got, err := get(t, &s3.GetObjectInput{Key: aws.String("conditional"), IfMatch: out.ETag})
		require.NoError(t, err)
		assert.Equal(t, "v1", got)
		_, err = get(t, &s3.GetObjectInput{Key: aws.String("conditional"), IfMatch: aws.String(`"0123456789abcdef0123456789abcdef"`)})
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, "PreconditionFailed", apiErr.ErrorCode())
	})

	t.Run("PresignedGet", func(t *testing.T) {
		put(t, "signed", "signed body")
		signed := presign(t, &s3.GetObjectInput{Key: aws.String("signed")})
		u, err := url.Parse(signed)
		require.NoError(t, err)
		require.NotEmpty(t, u.Query().Get("X-Amz-Signature"))
		status, body := httpGet(t, signed)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "signed body", body)

		// A tampered signature is refused, so the server really checks it.
		q := u.Query()
		q.Set("X-Amz-Signature", strings.Repeat("0", 64))
		u.RawQuery = q.Encode()
		status, _ = httpGet(t, u.String())
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("ListObjectsV2Order", func(t *testing.T) {
		// Byte order, which is not the order a naive directory walk
		// produces: '-' (0x2d) sorts before '/' (0x2f), and '/' before '0'.
		// (No key here is a prefix-directory of another: "a" beside "a/b"
		// is a file/directory conflict on a filesystem-backed server, as
		// it was on MinIO, and nothing in Pelican needs it.)
		keys := []string{"list/a0", "list/a/b", "list/a-b", "list/B", "list/a/c"}
		for _, k := range keys {
			put(t, k, k)
		}
		var listed []string
		p := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
			Bucket: &srv.Bucket, Prefix: aws.String("list/"), MaxKeys: aws.Int32(2),
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			require.NoError(t, err)
			for _, obj := range page.Contents {
				listed = append(listed, aws.ToString(obj.Key))
			}
		}
		assert.Equal(t, []string{"list/B", "list/a-b", "list/a/b", "list/a/c", "list/a0"}, listed)
	})

	t.Run("MultipartListAndAbort", func(t *testing.T) {
		part := bytes.Repeat([]byte("p"), 5<<20) // the S3 minimum part size
		complete, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: &srv.Bucket, Key: aws.String("mpu/complete"),
		})
		require.NoError(t, err)
		up, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &srv.Bucket, Key: aws.String("mpu/complete"), UploadId: complete.UploadId,
			PartNumber: aws.Int32(1), Body: bytes.NewReader(part),
		})
		require.NoError(t, err)
		_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket: &srv.Bucket, Key: aws.String("mpu/complete"), UploadId: complete.UploadId,
			MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{
				{PartNumber: aws.Int32(1), ETag: up.ETag},
			}},
		})
		require.NoError(t, err)
		head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &srv.Bucket, Key: aws.String("mpu/complete")})
		require.NoError(t, err)
		assert.Equal(t, int64(len(part)), aws.ToInt64(head.ContentLength))

		// An abandoned upload is listed, under its prefix only, with the
		// time it was started, and aborting it removes it.
		stale, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: &srv.Bucket, Key: aws.String("mpu/stale"),
		})
		require.NoError(t, err)
		_, err = client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &srv.Bucket, Key: aws.String("mpu/stale"), UploadId: stale.UploadId,
			PartNumber: aws.Int32(1), Body: bytes.NewReader(part),
		})
		require.NoError(t, err)
		listUploads := func(prefix string) []s3types.MultipartUpload {
			out, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket: &srv.Bucket, Prefix: aws.String(prefix),
			})
			require.NoError(t, err)
			return out.Uploads
		}
		uploads := listUploads("mpu/")
		require.Len(t, uploads, 1)
		assert.Equal(t, "mpu/stale", aws.ToString(uploads[0].Key))
		assert.Equal(t, aws.ToString(stale.UploadId), aws.ToString(uploads[0].UploadId))
		require.NotNil(t, uploads[0].Initiated)
		assert.WithinDuration(t, time.Now(), *uploads[0].Initiated, time.Minute)
		assert.Empty(t, listUploads("elsewhere/"))

		_, err = client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket: &srv.Bucket, Key: aws.String("mpu/stale"), UploadId: stale.UploadId,
		})
		require.NoError(t, err)
		assert.Empty(t, listUploads("mpu/"))
	})

	// ListMultipartUploads pages, resuming after NextKeyMarker until
	// IsTruncated is false.  This pages by key marker alone, which is all
	// that Pelican may rely on: versitygw rejects the upload-ID marker it
	// hands out itself (InvalidArgument), because it takes the marker to
	// name an upload of the key after the key marker, where S3 takes it to
	// name an upload of the key marker itself.
	t.Run("MultipartListPagination", func(t *testing.T) {
		keys := []string{"pages/a", "pages/b", "pages/c"}
		for _, key := range keys {
			out, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket: &srv.Bucket, Key: aws.String(key),
			})
			require.NoError(t, err)
			id := out.UploadId
			t.Cleanup(func() {
				_, _ = client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
					Bucket: &srv.Bucket, Key: aws.String(key), UploadId: id,
				})
			})
		}

		var listed []string
		input := &s3.ListMultipartUploadsInput{
			Bucket: &srv.Bucket, Prefix: aws.String("pages/"), MaxUploads: aws.Int32(1),
		}
		for pages := 1; ; pages++ {
			require.LessOrEqual(t, pages, len(keys), "the listing does not end")
			out, err := client.ListMultipartUploads(ctx, input)
			require.NoError(t, err)
			require.Len(t, out.Uploads, 1, "page %d", pages)
			listed = append(listed, aws.ToString(out.Uploads[0].Key))
			if !aws.ToBool(out.IsTruncated) {
				break
			}
			require.Equal(t, listed[len(listed)-1], aws.ToString(out.NextKeyMarker))
			input.KeyMarker = out.NextKeyMarker
		}
		assert.Equal(t, keys, listed)
	})

	// Last: it turns versioning on for the whole bucket.
	t.Run("Versioning", func(t *testing.T) {
		_, err := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
			Bucket: &srv.Bucket,
			VersioningConfiguration: &s3types.VersioningConfiguration{
				Status: s3types.BucketVersioningStatusEnabled,
			},
		})
		require.NoError(t, err)

		v1 := put(t, "versioned", "first")
		v2 := put(t, "versioned", "second")
		require.NotEmpty(t, aws.ToString(v1.VersionId))
		require.NotEqual(t, "null", aws.ToString(v1.VersionId))
		require.NotEqual(t, aws.ToString(v1.VersionId), aws.ToString(v2.VersionId))

		head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &srv.Bucket, Key: aws.String("versioned")})
		require.NoError(t, err)
		assert.Equal(t, aws.ToString(v2.VersionId), aws.ToString(head.VersionId))
		head, err = client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &srv.Bucket, Key: aws.String("versioned"), VersionId: v1.VersionId,
		})
		require.NoError(t, err)
		assert.Equal(t, aws.ToString(v1.VersionId), aws.ToString(head.VersionId))
		assert.Equal(t, int64(len("first")), aws.ToInt64(head.ContentLength))

		got, err := get(t, &s3.GetObjectInput{Key: aws.String("versioned"), VersionId: v1.VersionId})
		require.NoError(t, err)
		assert.Equal(t, "first", got)
		got, err = get(t, &s3.GetObjectInput{Key: aws.String("versioned")})
		require.NoError(t, err)
		assert.Equal(t, "second", got)

		signed := presign(t, &s3.GetObjectInput{Key: aws.String("versioned"), VersionId: v1.VersionId})
		status, body := httpGet(t, signed)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "first", body)
	})
}

// TestS3ServerTwoAtOnce: each test gets its own server, and two in one test
// must not be confused with each other.
func TestS3ServerTwoAtOnce(t *testing.T) {
	a := StartS3Server(t, "bucket-a")
	b := StartS3Server(t, "bucket-b")
	assert.NotEqual(t, a.Endpoint, b.Endpoint)
	ctx := context.Background()
	_, err := a.Client().HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &a.Bucket})
	require.NoError(t, err)
	_, err = b.Client().HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &b.Bucket})
	require.NoError(t, err)
	_, err = a.Client().HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &b.Bucket})
	require.Error(t, err, "server a should not have server b's bucket")
}

// TestS3ServerPortTaken: when another server already holds the chosen port,
// the attempt reports failure (so StartS3Server picks another port) rather
// than taking the occupant for the S3 server.  The occupant here is another
// S3 server, the likeliest one to grab the port and the hardest to tell
// apart: only the credentials differ.
func TestS3ServerPortTaken(t *testing.T) {
	occupant := StartS3Server(t, "taken")
	addr := strings.TrimPrefix(occupant.Endpoint, "http://")

	srv := &S3Server{
		Region:    s3ServerRegion,
		Bucket:    "taken",
		AccessKey: "pelican-test-" + randomHex(t, 8),
		SecretKey: randomHex(t, 20),
	}
	ok, log := srv.tryStart(t, addr)
	assert.False(t, ok, "an attempt on an occupied port must not succeed")
	assert.Contains(t, log, "address already in use", "the attempt should fail for want of the port")
}
