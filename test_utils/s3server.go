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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

// The S3-backed tests (the origin's S3 backend, cache tiering) run against a
// local S3 server.  That server is the Versity S3 Gateway (versitygw), over
// its posix backend; it replaced MinIO, whose open-source project is
// archived and no longer publishes binaries.  Tests should not depend on
// which server it is: they get an S3Server and talk S3 to it.
const (
	// s3ServerBinary is the server executable looked up on PATH.
	s3ServerBinary = "versitygw"

	// requireS3ServerEnv, when set, turns a missing S3 server from a skip
	// into a failure.  CI sets it wherever it installs the server, so that
	// losing the binary cannot silently stop the S3-backed tests from
	// running.  (Not PELICAN_*: the configuration reads every variable with
	// that prefix as a setting.)
	requireS3ServerEnv = "TEST_REQUIRE_S3_SERVER"

	// s3ServerRegion is the region the server reports and expects requests
	// to be signed for.
	s3ServerRegion = "us-east-1"
)

// S3Server is a running local S3 server with one bucket, created empty and
// with versioning available (but, as on AWS, not enabled: a test that wants
// a versioned bucket calls PutBucketVersioning).  Addressing is path-style.
type S3Server struct {
	// Endpoint is the base URL of the S3 API, e.g. http://127.0.0.1:41234.
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
}

// SkipIfNoS3Server skips the test if the S3 server binary is not on PATH,
// or fails it if TEST_REQUIRE_S3_SERVER is set.
func SkipIfNoS3Server(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(s3ServerBinary); err != nil {
		if os.Getenv(requireS3ServerEnv) != "" {
			t.Fatalf("%s not found on PATH, and %s is set", s3ServerBinary, requireS3ServerEnv)
		}
		t.Skipf("%s not found on PATH; skipping S3-backed test", s3ServerBinary)
	}
}

// StartS3Server launches an S3 server on a loopback port, creates bucket in
// it, and returns once the bucket exists.  The server and its storage are
// removed when the test completes.  It skips the test (or fails it, see
// SkipIfNoS3Server) when no server is installed.
func StartS3Server(t *testing.T, bucket string) *S3Server {
	t.Helper()
	SkipIfNoS3Server(t)

	// versitygw cannot listen on port 0 and report the port it got, so the
	// port is chosen here, which leaves a window for something else to take
	// it first.  Each server gets its own random credentials, and the server
	// counts as up only once a request signed with them has created the
	// bucket, so a port taken by anything else -- another test's server
	// included -- is never mistaken for ours; the server then fails to bind
	// and exits, and we try again on another port.  (That is so on Linux.
	// On macOS a bind to 127.0.0.1 succeeds beside a wildcard listener on
	// the same port and takes its loopback traffic; the server that answers
	// is still ours, but the other listener loses its loopback clients.  The
	// window is a few milliseconds wide, so this is not guarded against.)
	srv := &S3Server{
		Region:    s3ServerRegion,
		Bucket:    bucket,
		AccessKey: "pelican-test-" + randomHex(t, 8),
		SecretKey: randomHex(t, 20),
	}
	const attempts = 5
	var lastLog string
	for range attempts {
		ok, log := srv.tryStart(t, freeLoopbackAddr(t))
		if ok {
			return srv
		}
		lastLog = log
	}
	t.Fatalf("%s did not start after %d attempts; last log:\n%s", s3ServerBinary, attempts, lastLog)
	return nil
}

// tryStart runs one server listening on addr.  It returns true once
// the server is up and the bucket exists.  It returns false, with the
// server's log, if the server exited first (as it does when another process
// took the port); any other failure fails the test.
func (srv *S3Server) tryStart(t *testing.T, addr string) (bool, string) {
	t.Helper()
	dataDir := t.TempDir()
	rootDir := filepath.Join(dataDir, "root")
	versionDir := filepath.Join(dataDir, "versions")
	require.NoError(t, os.Mkdir(rootDir, 0o755))
	require.NoError(t, os.Mkdir(versionDir, 0o755))

	cmd := exec.Command(s3ServerBinary,
		"--port", addr,
		"--region", srv.Region,
		"--quiet",
		"posix",
		// Without a versioning directory the gateway refuses
		// PutBucketVersioning.
		"--versioning-dir", versionDir,
		rootDir,
	)
	// The gateway reads much of its configuration from the environment
	// (VGW_* and others: TLS, IAM, audit and event targets), so it gets
	// only what it needs rather than whatever the developer has set.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.Getenv("TMPDIR"),
		"ROOT_ACCESS_KEY=" + srv.AccessKey,
		"ROOT_SECRET_KEY=" + srv.SecretKey,
	}
	logPath := filepath.Join(dataDir, "server.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	defer logFile.Close() // the child holds its own descriptor
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start(), "failed to start %s", s3ServerBinary)

	exited := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()
	stop := func() {
		_ = cmd.Process.Kill()
		<-exited
	}
	readLog := func() string {
		data, _ := os.ReadFile(logPath)
		return string(data)
	}

	srv.Endpoint = "http://" + addr
	client := srv.Client()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := srv.createBucket(ctx, client)
		cancel()
		if err == nil {
			t.Cleanup(stop)
			return true, ""
		}
		select {
		case <-exited:
			return false, "exit status: " + errString(waitErr) + "\n" + readLog()
		default:
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("%s at %s never created bucket %q (last error: %v); log:\n%s",
				s3ServerBinary, addr, srv.Bucket, err, readLog())
		}
		select {
		case <-exited:
			return false, "exit status: " + errString(waitErr) + "\n" + readLog()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (srv *S3Server) createBucket(ctx context.Context, client *s3.Client) error {
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(srv.Bucket)})
	var owned *s3types.BucketAlreadyOwnedByYou
	if errors.As(err, &owned) {
		// An earlier attempt's response was lost after the bucket was made.
		return nil
	}
	return err
}

// Client returns an S3 client for the server, signed with its credentials and
// using path-style addressing, for tests that need operations the code under
// test has no reason to expose (enabling versioning, say).
func (srv *S3Server) Client() *s3.Client {
	return s3.New(s3.Options{
		Region:       srv.Region,
		BaseEndpoint: aws.String(srv.Endpoint),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(srv.AccessKey, srv.SecretKey, ""),
		// Fail fast while the server is still starting; tests that want
		// retries can configure their own client.
		RetryMaxAttempts: 1,
	})
}

// WriteCredentialFiles writes the access and secret keys to files in a fresh
// temporary directory, for configuration that takes key files, and returns
// their paths.
func (srv *S3Server) WriteCredentialFiles(t *testing.T) (accessKeyfile, secretKeyfile string) {
	t.Helper()
	dir := t.TempDir()
	accessKeyfile = filepath.Join(dir, "access-key")
	secretKeyfile = filepath.Join(dir, "secret-key")
	require.NoError(t, os.WriteFile(accessKeyfile, []byte(srv.AccessKey), 0o600))
	require.NoError(t, os.WriteFile(secretKeyfile, []byte(srv.SecretKey), 0o600))
	return accessKeyfile, secretKeyfile
}

// freeLoopbackAddr returns a 127.0.0.1 address whose port was free a moment
// ago.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func errString(err error) string {
	if err == nil {
		return "0"
	}
	return err.Error()
}
