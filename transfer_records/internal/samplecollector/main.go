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

// Command samplecollector is a minimal central monitoring service: it subscribes
// to one Pelican server's transfer-record change feed and writes what it
// receives to stdout as NDJSON.
//
// It exists to exercise the collection contract end to end -- authentication,
// cursor resumption after an outage, and the shape of a record -- and as a
// worked example of what a real collector has to implement, which is not much:
// a replicate.Sink and a call to changefeed.Pull.
//
// It is deliberately not a shipped binary. A real service aggregates many
// sources, stores records in an external database, and forwards them onward;
// see docs/transfer-records-design.md §6 for where that belongs. A sample that
// gets deployed is a sample that grows features.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/PelicanPlatform/classad/changefeed"
	"github.com/PelicanPlatform/classad/db/replicate"
)

func main() {
	var (
		baseURL    = flag.String("url", "", "base URL of the Pelican server's transfer-record feed (required)")
		table      = flag.String("table", "transfers", "table to follow")
		src        = flag.String("src", "", "source label to subscribe as (defaults to the server's own)")
		subscriber = flag.String("subscriber", "", "durable subscription id; the source attributes acknowledgements to it")
		token      = flag.String("token", "", "bearer token with the monitoring.scrape scope")
		tokenFile  = flag.String("token-file", "", "file holding the bearer token")
		cursorAt   = flag.String("cursor-file", "", "file in which to persist the resume cursor")
		count      = flag.Int("count", 0, "exit after this many records (0 means run until interrupted)")
	)
	flag.Parse()

	if *baseURL == "" {
		fmt.Fprintln(os.Stderr, "samplecollector: -url is required")
		os.Exit(2)
	}

	bearer := *token
	if bearer == "" && *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "samplecollector: reading token: %v\n", err)
			os.Exit(1)
		}
		bearer = string(raw)
	}

	sink := &stdoutSink{cursorFile: *cursorAt, want: *count}
	if err := sink.restore(); err != nil {
		fmt.Fprintf(os.Stderr, "samplecollector: restoring cursor: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *count > 0 {
		sink.done = stop
	}

	cfg := changefeed.PullConfig{
		BaseURL:    *baseURL,
		Table:      *table,
		Src:        *src,
		Subscriber: *subscriber,
		Token:      bearer,
	}

	if err := changefeed.Pull(ctx, cfg, sink); err != nil {
		fmt.Fprintf(os.Stderr, "samplecollector: %v\n", err)
		os.Exit(1)
	}
}

// stdoutSink prints each record and remembers where it got to.
//
// The cursor is what makes an outage survivable: on restart the collector
// resumes from the last position it durably recorded, so records written while
// it was away are delivered rather than missed. Commit is called only once the
// records before it have been dealt with, which is why persisting the cursor
// belongs there and not in Apply.
type stdoutSink struct {
	mu         sync.Mutex
	cursor     []byte
	cursorFile string
	seen       int
	want       int
	done       func()
}

func (s *stdoutSink) Apply(c replicate.Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.Kind != replicate.KindUpsert || c.Ad == nil {
		// Resets and gaps are advisory. A real collector would record a gap as
		// evidence that records were dropped before it collected them.
		if c.Kind == replicate.KindGap {
			fmt.Fprintf(os.Stderr, "samplecollector: gap reported by the source; some records were not collected\n")
		}
		return nil
	}

	raw, err := c.Ad.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling record %s: %w", c.Key, err)
	}
	line, err := json.Marshal(map[string]any{
		"key":    c.Key,
		"src":    c.Src,
		"record": json.RawMessage(raw),
	})
	if err != nil {
		return err
	}
	fmt.Println(string(line))

	s.seen++
	if s.want > 0 && s.seen >= s.want && s.done != nil {
		s.done()
	}
	return nil
}

func (s *stdoutSink) Commit(cursor []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = cursor
	if s.cursorFile == "" {
		return nil
	}
	// Written via a temporary file and renamed, so an interrupted write leaves
	// the previous cursor intact rather than a truncated one. A collector that
	// loses its cursor re-reads from the source's floor; one that reads a
	// corrupt cursor may not notice.
	tmp := s.cursorFile + ".tmp"
	if err := os.WriteFile(tmp, cursor, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cursorFile)
}

func (s *stdoutSink) Cursor() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor
}

func (s *stdoutSink) restore() error {
	if s.cursorFile == "" {
		return nil
	}
	raw, err := os.ReadFile(s.cursorFile)
	if os.IsNotExist(err) {
		return nil // first run: start from the beginning
	}
	if err != nil {
		return err
	}
	s.cursor = raw
	fmt.Fprintf(os.Stderr, "samplecollector: resuming from the cursor in %s\n", filepath.Base(s.cursorFile))
	return nil
}
