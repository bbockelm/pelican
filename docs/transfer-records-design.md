# Transfer Records

> **Status:** Design / architecture reference, reflecting the implementation in the `transfer_records/` package.
>
> **Scope:** How a Pelican server keeps a local, queryable history of the transfers it has served, and how a central service collects that history. Intended for developers working on the module and for reviewers of the access-control decisions in §5.

## 1. Overview

A Pelican server records every transfer it serves as a ClassAd in an embedded HTCondor database, and exposes those records to a central monitoring service over an authenticated change feed.

The arrangement is deliberately **local-first**. The store on the node is the system of record; collection is a subscription a central service opens against it. Nothing in the data path waits on that service, and the server is unaffected if it is absent for days. A monitoring system that can slow down or break data serving is worse than no monitoring system.

This is independent of how the server is deployed. It works the same for a systemd-managed origin, a containerised cache, and a daemon supervised by `condor_master` (see [condor-daemon-design.md](condor-daemon-design.md), which uses this feature but is not required by it).

It is off by default: `Monitoring.EnableTransferRecords`.

```
                 ┌──────────────── Pelican server ─────────────────┐
  a transfer ──► │ TransferEvent ──┬──► XRootD-format shoveler     │
  completes      │                 └──► transfer_records store     │
                 │                        ├── transfers (archive)  │
                 │                        └── transfers_active     │
                 │                                 │               │
                 │                        change feed (HTTPS,      │
                 │                        token-gated)             │
                 └─────────────────────────────────┼───────────────┘
                                                   │ subscribe + ack
                                        central monitoring service
```

## 2. Where records come from

`metrics.TransferEvent` already existed as a protocol-neutral description of a completed transfer — path, byte and operation counts, client address, user DN, issuer, project, user agent, start and end times — emitted by the POSIXv2 origin and the V2 cache. Recording is therefore a second consumer of an existing hook, not new instrumentation.

### 2.1 Fan-out, and why it lives in `Close`

`EmitTransferEvent` delivers a completed transfer to any number of registered consumers. The XRootD-format shoveler is one; the record store is another. Neither can disable the other, and all four combinations of the two are supported and tested.

The fan-out is in `TransferMonitor.Close` rather than in `EmitTransferEvent`, because that is where both emission paths converge: the cache's one-shot `EmitTransferEvent`, and the origin's *streaming* monitor, which is held across a request and closed at the end. Fanning out from `EmitTransferEvent` alone would have silently missed every origin transfer — and the cache tests would still have passed.

It is deferred inside `Close`, so a monitoring packet that fails to build costs the shoveler stream and not the record.

### 2.2 The shoveler's knob governs the shoveler

`BeginTransferMonitor` returns a monitor even when `Shoveler.Enable` is false: inert as to packets, live as to consumers. Returning nil — correct when the shoveler was the only consumer — would let an unrelated subsystem's setting switch off transfer recording for everyone. For the same reason the cache no longer short-circuits on `Shoveler.Enable` before emitting.

### 2.3 Consumers are isolated

Each consumer receives its own copy of the record. The registry lock is released before any consumer runs, so one cannot block registration or another. A consumer that panics loses that record, with the panic logged, rather than unwinding into the request that produced it.

Consumers are called on the goroutine that finished the transfer and must return promptly; buffering is the consumer's own responsibility. That is what stops a slow sink applying backpressure to serving.

### 2.4 Observers see the whole transfer

A consumer that only wants completed transfers registers with `RegisterTransferEventConsumer`. One that maintains a view of what is happening *now* registers as an `ActiveTransferObserver` and is told when a transfer begins, progresses, and ends.

The store is an observer, not a plain consumer, and that distinction matters: an observer archives the completed record itself, so registering it as both would archive every transfer twice. That is a miscount nothing surfaces until the numbers are wrong, so there is a test asserting one transfer produces exactly one record.

## 3. The store

An embedded `classad/db` catalog under `Monitoring.TransferRecordsLocation`, holding two tables.

### 3.1 Two tables, because they have different shapes

- **`transfers`** — an archive table: append-only, rotated, and the table a collector normally follows.
- **`transfers_active`** — a mutable table holding transfers still running, updated as they progress.

The archive must stay append-only for a subscriber's cursor to mean anything; a running transfer's row changes as it goes. Keeping them separate is what lets both be true.

The split also gives each of htcondordb's maintenance loops something to do. An archive-only catalog would leave the self-tuning pass idle, since it operates on the mutable collection rather than on archive tables.

### 3.2 A crash is accounted for, not lost

Rows can only survive a restart in `transfers_active` if the server stopped while transfers were running. On startup `Reconcile` moves them into the archive marked `abandoned`.

That is the honest outcome. The server cannot know whether those transfers finished; recording them as completed would misreport, and discarding them would be silent data loss. A completed transfer also reuses its in-progress key, so a collector that saw both rows recognises one transfer rather than counting two.

### 3.3 Retention is a byte cap

`Monitoring.TransferRecordsMaxSize` bounds the archive's sealed segments; rotation drops the oldest first. Bytes rather than time because it is the bound an operator can size a filesystem against, and it degrades predictably: a busy server keeps a shorter window rather than overrunning a budget expressed in days.

It is a hard bound, not a retention period. A server nobody collects from fills to the limit and then begins forgetting.

Dropping is **not** coordinated with what has been collected. The change feed's acknowledgement registry does compute a garbage-collection floor, so collection-aware reclamation is available and is the natural next step; the byte cap remains the backstop, since an absent or permanently-behind subscriber must not be able to fill the disk.

### 3.4 Maintenance

Two loops at different cadences, following htcondordb:

| Action                                               | Cadence           | Cost                          |
| ---------------------------------------------------- | ----------------- | ----------------------------- |
| `Rotate` — drop sealed segments over the byte cap    | hourly            | cheap; unlinks whole segments |
| `Reindex` — build sidecars for newly sealed segments | hourly, same pass | cheap and idempotent          |
| Self-tuning on the mutable table                     | 15 minutes        | moderate                      |

Rotation and reindexing share a pass because rotation is what creates the newly sealed segments reindexing then covers. `RetrainDict` and `Rewrite` are **not** on any loop: both reseal every segment in place, and a tuning pass that triggered one would rewrite the whole archive on its own cadence.

### 3.5 Indexing, and what is expensive to change later

`CompletionDate` is the archive's zone-mapped attribute, so "everything since T" — the query a collector issues — prunes whole segments instead of scanning. It is named as htcondordb's history table names it, so the same tooling and the same age-based retention rule apply unchanged.

Index sets can be revised after the fact: sidecars are derived data, and `AddIndex` rebuilds them over existing segments. The hot set cannot, cheaply — it is baked into the record encoding at append time, so changing it retroactively means re-encoding every segment. Since the hot set only affects decode speed and never query results, and since retention turns the archive over on a bounded schedule anyway, a hot-set change applies to new segments and old ones age out.

## 4. The record

Attribute names are exported constants, because a collector binds to them: renaming one is a wire change, not a refactor.

The projection is field-for-field rather than clever — a collector should be readable without consulting Pelican's source. Two properties are deliberate:

- **Unknown fields are absent, not empty.** An absent attribute says "not measured"; an empty string would say "measured and blank".
- **Every record carries its server's identity** — name, type, version, federation — so it is interpretable alone, without a join against whatever the collector knows about its sources.

Duration is a float. Most cache hits complete in well under a second, and integer seconds would record every one of them as zero.

## 5. Collection

### 5.1 Pull, not push

A central service subscribes and pulls. Three reasons, all of which shaped the interface:

- **Authorization stays simple as the federation grows.** A server authorizes one relationship — the federation — rather than holding a write credential for an aggregation endpoint and being configured with its location. Push would mean provisioning and rotating a credential per server.
- **Rate is the collector's to manage.** It chooses interval and concurrency. With push, N servers each decide when to send and the aggregator absorbs whatever arrives, which is worst exactly when it has just come back from an outage.
- **Reachability already exists.** Servers behind firewalls are reached through Pelican's broker, which exists to reverse connections from the director. A puller can use the same path.

### 5.2 The feed

`classad/changefeed`'s handler, mounted on the web engine behind Pelican's token middleware. The upstream package is transport-neutral and documents that it expects to be token-gated in front, so this is the arrangement it was built for.

It serves SSE `subscribe` and `POST ack` beneath `/api/v1.0/transfer_records`, reading through `db.Watch` and never writing. Both tables are watchable, so the two-table split needs no special handling.

A subscriber is a `replicate.Sink` plus a call to `changefeed.Pull`, which resumes from the sink's cursor on every reconnect and acknowledges what it has durably stored. `transfer_records/internal/samplecollector` is a worked example: it writes NDJSON to stdout and persists its cursor through a temporary file and a rename, so an interrupted write leaves the previous cursor intact rather than a truncated one.

### 5.3 Authorization

Reading the feed requires a token with the `monitoring.raw` scope.

**The subscriber identity comes from the token's subject**, not from a request parameter, and a token that authenticates but names no subject is refused. This is not tidiness: acknowledgements advance a garbage-collection floor, so a client free to name itself could acknowledge on another subscriber's behalf and cause records to be dropped before that subscriber collected them. An anonymous shared cursor has the same failure mode.

**A separate scope from `monitoring.scrape`, deliberately.** Metrics are aggregates; these records name the object transferred, the address that asked for it, and the user who authenticated. Granting both with one scope would mean anyone permitted to scrape a server could also reconstruct who transferred what. A test asserts a `monitoring.scrape` token is refused, so the separation cannot quietly erode.

### 5.4 Outage behaviour

- **Nothing collecting** — appends continue, the archive fills to its cap, then the oldest records rotate away. `records_dropped_by_rotation` and `oldest_retained_record_timestamp` make the loss visible.
- **A subscriber reconnects** — it resumes from its cursor and receives what it missed, without redelivery of what it already had.
- **A subscriber falls further behind than retention** — records are gone. The acknowledgement registry lets the source see each subscriber's watermark, so this is detectable at the source rather than only inferable by the collector.

## 6. Where the central service belongs

**A Pelican server module**, alongside the director and registry, rather than a separate program.

The deciding argument is authorization. The service must validate federation tokens and Pelican scopes, and that machinery is Pelican's. Anywhere else it would either import Pelican wholesale or reimplement token validation, scope definitions, and federation discovery, then keep them in step indefinitely. It is also a federation-level service, which is what `pelican-server` already hosts.

What it must **not** become is a time-series database. Storage, SQL query, and forwarding belong to htcondordb — embedded for a small federation, external for a large one, addressed over `dbrpc`. Pelican supplies the federation-facing endpoint and its authorization; htcondordb supplies the engine.

The sample collector stays a test fixture rather than becoming that service. A sample that gets deployed is a sample that grows features.

## 7. Configuration

| Parameter                            | Purpose                                                |
| ------------------------------------ | ------------------------------------------------------ |
| `Monitoring.EnableTransferRecords`   | Off by default. Enables recording and the change feed. |
| `Monitoring.TransferRecordsLocation` | Catalog directory.                                     |
| `Monitoring.TransferRecordsMaxSize`  | Hard bound on archive bytes; default 1 GiB.            |

Not supported on Windows: the store relies on memory-mapped segment files. Enabling it there is an error rather than a silent no-op, so an operator is told instead of finding an empty feed later.

## 8. Testing

| Tier                  | Coverage                                                                                                                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Fan-out               | All four combinations of shoveler and consumer; panic containment; unregistration; final counts reach the consumer.                                                                              |
| Store                 | Projection; unknown fields omitted; archive durability across reopen; the active-row lifecycle; crash recovery via `Reconcile`; one transfer producing exactly one record.                       |
| Feed                  | Delivery to a real `changefeed.Pull` subscriber; refusal of an unidentified caller; cursor resumption across a simulated outage with no redelivery.                                              |
| Authorization         | An authenticated pull through the real middleware with a minted token; a token carrying a different scope refused 403, which shows the scope rather than authentication is what guards the feed. |
| Under `condor_master` | The store opens and the feed is mounted and gated on a real supervised daemon.                                                                                                                   |

Not covered: minting a token against a *separate* `pelican-server` process's issuer and pulling from it. The route is proven mounted and gated on a real daemon, and the auth and pull are proven in-process; only the cross-process token provisioning is unexercised, and that is Pelican's ordinary issuer machinery.

## 9. Open questions

1. **Schema stability.** Are the record attributes a committed interface or explicitly provisional? Consumers will assume committed unless told. Deferred until closer to a release.
1. **The retention default.** The byte cap is the collection-lag tolerance, and the window it buys depends on record rate — which wants a measurement per service class rather than a guess.
1. **Collection-aware reclamation** using the acknowledgement floor, so a byte cap is not the only thing standing between an outage and lost records.
