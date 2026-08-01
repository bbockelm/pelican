# Running pelican-server as an HTCondor Daemon

> **Status:** Design / architecture reference, reflecting the implementation in the `condor/` package.
>
> **Scope:** How `pelican-server` runs as a daemon supervised by `condor_master` — configured from HTCondor's configuration, dropping to the `condor` account while still reading root-owned pool credentials, and advertising to a `condor_collector`. Intended for developers working on the module and for reviewers of the privilege model in §5.

## 1. Overview

`pelican-server` has two deployment modes. In the usual one it reads Pelican's YAML configuration, is supervised by systemd, and advertises to a Pelican director. In the other it is a first-class HTCondor daemon: `condor_master` starts and supervises it, its configuration comes from the pool, it presents the pool's SSL host credential, and it advertises to a `condor_collector` alongside every other daemon.

The motivation is deployment consolidation. A site already running an HTCondor pool gets its Pelican caches and origins supervised, configured, monitored, and authorized by machinery it already operates, instead of a parallel stack.

Detection is environmental — `condor_master` passes `CONDOR_INHERIT` to its children — so a host that does not run HTCondor behaves exactly as it always has. No configuration selects the mode, because the answer is needed before any configuration is read.

```
                 ┌─ CONDOR_INHERIT in the environment?
pelican-server ──┤
                 └─ no ──► standalone: today's behavior, unchanged
                    yes ─► HTCondor mode
```

### 1.1 What HTCondor mode changes

|                 | Standalone                               | Under `condor_master`                                  |
| --------------- | ---------------------------------------- | ------------------------------------------------------ |
| Configuration   | Pelican YAML and `PELICAN_*` environment | Pool configuration, layered over Pelican's (§4)        |
| Command line    | cobra CLI                                | Not parsed; DaemonCore owns argv (§3.3)                |
| Privileges      | Optional permanent drop                  | Reversible drop, retaining root credential reads (§5)  |
| TLS certificate | Pelican's own                            | The pool's SSL host credential, when one exists (§5.6) |
| Lifecycle       | systemd, Pelican's signal handling       | `condor_master`; the framework owns signals (§3.2)     |
| Discovery       | Pelican director                         | Director *and* `condor_collector` (§6)                 |
| Control         | Signals                                  | Signals plus a CEDAR command port (§3.4)               |

### 1.2 Non-goals

- **XRootD.** HTCondor mode runs Pelican's native-Go backends only; see §2. This is enforced, not assumed.
- **Shared-port multiplexing for HTTPS.** The daemon binds its own port. Pelican speaks HTTPS to clients that know nothing about CEDAR, so fronting it with the pool's shared port would add a hop for no benefit. The command port does use shared port, because that is CEDAR.
- **Replacing the director advertisement.** Collector advertisement is additive; a server in a federation still advertises to its director.

### 1.3 What this builds on

`github.com/bbockelm/golang-htcondor` (Apache 2.0, pure Go) supplies most of the HTCondor side:

| Package                          | What it provides                                                                                                                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `config`                         | A complete Go implementation of the HTCondor configuration language — lexer, parser, metaknobs, subsystem and local-name scoping. No `condor_config_val` subprocess, no CGO.               |
| `daemon`                         | `condor_master` detection, `DC_SET_READY`, the `DC_CHILDALIVE` keepalive, parent-death monitoring, SIGTERM/SIGHUP lifecycle, HTCondor-format logging, the default `DC_*` command handlers. |
| `daemon.PublishAd` / `Advertise` | The DaemonCore `publish()` analogue plus the update loop: sequence numbers, `DAEMON_SHUTDOWN` evaluation, INVALIDATE on exit.                                                              |
| `droppriv`                       | HTCondor's reversible `set_priv` model, per-thread.                                                                                                                                        |
| `CredentialCache`                | Caching, privileged credential reader satisfying CEDAR's hooks. Central to §5.                                                                                                             |

Transfer recording, which HTCondor mode enables but does not require, is described separately in [transfer-records-design.md](transfer-records-design.md).

## 2. Native backends only

Pelican already has XRootD-free serving paths for every server type, and HTCondor mode uses exactly those:

- **Origin** — `OriginStorageType.UsesXRootD()` is false for `posixv2`, `ssh`, `s3v2`, `httpsv2`, and `globusv2`.
- **Cache** — `Cache.EnableV2` selects the persistent cache, which registers handlers on the Gin engine with no XRootD process.
- **Director, registry, broker** never involved XRootD.

So this is not a reduced Pelican; it is Pelican restricted to its native backends. The result is a **single process with no children**, which is what makes the DaemonCore contract fit: one pid for the master to supervise, one SIGTERM to shut down, no child lifecycle to reconcile against the master's own restart logic.

**This is enforced at startup.** A configuration naming an XRootD-backed `Origin.StorageType`, or a cache without `Cache.EnableV2`, is refused with an error naming the native alternative. Without the check such a daemon starts and then tries to launch XRootD, failing later and further from the cause.

The check runs inside the configuration provider rather than at startup proper, because that is the first moment Pelican's configuration exists at all (§4.1). Modules that never used XRootD are unaffected — a director has no storage type, and rejecting one for a setting it does not use would be its own bug.

## 3. Process lifecycle

### 3.1 Startup

```
1.  Probe for condor_master (environmental).
2.  Parse the DaemonCore arguments that matter (§3.3).
3.  Load the HTCondor configuration, scoped by subsystem and local name.
4.  Drop privileges to condor, reversibly (§5).
5.  Register the configuration provider (§4.1) and the TLS credential loader (§5.6).
6.  Obtain the command-port listener; publish the address file (§3.4).
7.  Bind the HTTPS listener from PELICAN_PORT.
8.  launchers.LaunchModules — which is where Pelican's own configuration finally loads.
9.  DC_SET_READY; keepalive; collector advertisement (§6).
```

Step 4 before step 8 inverts the standalone ordering, where Pelican does privileged work as root and drops afterwards. Here everything Pelican creates is created *as* `condor` and owned by it, which is simpler and safer than creating root-owned files and hoping the dropped process can still use them. Only HTCondor's own credentials need privilege, and those are read, never written.

### 3.2 Signals belong to the framework

Pelican and HTCondor disagree about SIGHUP: Pelican treats it as "restart the process", a supervisor sends it to mean "reload configuration". Two sets of handlers racing over one signal is not workable, so in HTCondor mode the daemon framework owns signal disposition and Pelican's own handling is switched off through `launchers.WithoutSignalHandling`.

Cancelling the context then becomes the termination path, and it performs the same graceful teardown — including the in-flight-transfer drain — that a signal would. An embedder that turned off signal handling and silently lost that drain would be worse off than one that never had the option.

### 3.3 The command line is not Pelican's

A daemon named in `DC_DAEMON_LIST` is launched with DaemonCore's own arguments: the subsystem name, and `-local-name`. A cobra command tree rejects those as an unknown command before any Pelican code runs.

So in HTCondor mode **cobra never sees argv**. `dispatchCondorDaemon` runs ahead of the CLI and, when the process was started by `condor_master`, calls the daemon directly. Filtering DaemonCore's arguments back out would mean tracking what the master passes across HTCondor versions in order to arrive at an empty flag set anyway.

Everything that would have been a flag is configuration instead, which is the right shape for a daemon nobody launches by hand:

| Knob                                   | Replaces                                                                    |
| -------------------------------------- | --------------------------------------------------------------------------- |
| `PELICAN_SERVER_MODULES`               | `--module`, spelled as the translation layer spells `Server.Modules` (§4.2) |
| `PELICAN_PORT`, `PELICAN_BIND_ADDRESS` | the listen address                                                          |
| `PELICAN_CONFIG_FILE`                  | `--config`, for the structured parameters §4.3 declines to translate        |

**But argv is still read.** `-local-name` changes how configuration resolves — HTCondor looks through `<SUBSYS>.<LOCALNAME>.<KEY>` and `<LOCALNAME>.<KEY>` before the bare name, which is how two instances of a daemon on one host are configured differently. Discarding it would produce a daemon that reads the shared values, starts cleanly, and is misconfigured with nothing to show for it. `ParseDaemonCoreArgs` takes `-local-name` and `-sock` and skips the rest, because the master passes version-dependent arguments and rejecting unrecognized ones would turn every future addition into a pool that will not start after an upgrade.

Note that `daemon.Options.LocalName` alone is not sufficient, though it looks as if it should be: that field only scopes the session-database filename, and the framework otherwise builds its configuration with a bare `config.New()`. Pelican constructs the `Config` itself with both subsystem and local name.

### 3.4 The command port

A CEDAR server, so `condor_reconfig` and `condor_off` reach the daemon directly rather than only as signals relayed by the master. Authorization comes from the pool's own security configuration, so commands are gated exactly as on a C++ daemon — `DC_NOP` at ALLOW, reconfigure and shutdown at ADMINISTRATOR.

The listener is whatever the framework can obtain: under `DC_DAEMON_LIST`, the socket the master pre-created and passed down; otherwise a self-registered shared-port endpoint; failing both, a loopback bind. Loopback deliberately — a command port no supervisor arranged should not be reachable off-host.

**Pelican writes its own address file.** The tools locate a daemon through the collector or `<SUBSYS>_ADDRESS_FILE`, and `PELICAN` is not a subsystem they resolve by name; the Go framework reads address files but does not write one. Without it the port is reachable in principle and not in practice. It is written through a temporary file and renamed, and removed on shutdown so a stale address does not outlive the daemon.

This port is separate from and additional to the HTTPS port clients use: two protocols, two audiences.

### 3.5 Reconfigure

`condor_reconfig` reloads the HTCondor configuration, flushes cached credentials, and feeds the changes into **Pelican's own hot-reload mechanism** — `param.MultiSet`, which rebuilds the cached configuration and fires the callbacks modules register through `param.RegisterCallback`. A subsystem watching a parameter is notified the ordinary way rather than through a path invented for this mode.

Only parameters Pelican marks runtime-configurable are applied. The rest are **reported by name**. Half-applying a configuration would leave the daemon matching neither the old state nor the new one, and naming them is what stops an operator assuming the reconfigure was enough. Object-typed parameters are left alone entirely: they describe structure the modules bound at startup.

## 4. Configuration

### 4.1 HTCondor configuration is an additional layer

It does not replace Pelican's; it layers over it, with the same precedence a config file has. Pelican's generated defaults load first, the pool's values override them, and environment variables still win last.

Framing it as a merge layer rather than a replacement keeps one code path instead of two parallel configuration systems, and preserves the several hundred accumulated defaults that encode what a working server needs.

**The ordering constraint that shapes everything here:** `config.InitConfigInternal` — which loads Pelican's YAML, applies derived defaults, and refreshes the `param.*` cache — is called from the *first line of* `config.InitServer`, which runs inside `LaunchModules`. Anything earlier sees **unset** parameters, silently: `param.Server_WebPort` reads 0 and `Server_WebHost` reads empty, with no error.

So the translation cannot run before Pelican's configuration loads; it has to run *inside* that load. `config.RegisterExternalConfigProvider` installs a provider that `InitConfigInternal` calls after every config-file merge and before environment variables are recorded. The hook is generic, so the config package takes no dependency on the daemon mode.

The same constraint is why the listen address comes from `PELICAN_PORT` rather than `Server.WebPort` (§3.3), and why `Server.WebPort` is then set to 0 so the existing `UpdateConfigFromListener` path adopts the bound address into the URLs derived from it.

### 4.2 Knob names need no mapping table

A parameter's knob is its name upper-cased with dots replaced by underscores, prefixed `PELICAN_` — `Cache.EnableV2` is `PELICAN_CACHE_ENABLEV2`. This is deliberately the same spelling as the parameter's environment variable, so operators learn one rule, the documentation generator already emits it, and there is no second table to drift out of step with the parameter list. A test asserts the two spellings stay identical.

Values merge as **strings**, exactly as environment variables arrive, and viper's existing decode hooks turn them into bools, ints, durations and slices. No per-parameter type table is needed, which is one fewer thing to keep in step with `parameters.yaml`.

### 4.3 Structured parameters, and how they cannot be forgotten

Object-typed parameters are lists of structures, which a flat string namespace cannot hold. Each is expressed as a per-item knob family — a list knob naming the items, and per-field knobs beneath each name:

```
PELICAN_ORIGIN_EXPORTS = public, protected

PELICAN_ORIGIN_EXPORT_PUBLIC_FEDERATIONPREFIX = /ospool/public
PELICAN_ORIGIN_EXPORT_PUBLIC_STORAGEPREFIX    = /data/public
PELICAN_ORIGIN_EXPORT_PUBLIC_CAPABILITIES     = PublicReads, Reads
```

JSON-in-a-knob is deliberately not supported: it is invisible to `condor_config_val`, unpleasant to diff, and cannot participate in `$(...)` expansion or metaknobs. The point of the exercise is that an HTCondor administrator can manage Pelican with HTCondor tools.

The list knob is authoritative rather than the item set being inferred from a prefix scan, so a half-written or commented-out item is inert instead of silently active, and a named item missing a required field is a startup error naming both.

**Adding an object-typed parameter breaks the build until it is handled.** The generator emits a constructor taking one argument per object-typed parameter in `parameters.yaml`; the handler registry calls it. Introduce a new one and the call site stops compiling:

```
condor/object_params.go: not enough arguments in call to NewObjectParamSet
```

Arity is what the compiler can check — every argument has the same type — so each handler also declares which parameter it is for, and the constructor panics on a mis-ordered slot.

The failure this prevents is silence: a developer adds an object-typed parameter, nothing objects, and an HTCondor-mode deployment quietly ignores that section of its configuration, with the omission living in a different package from the change. **Refusal is a legitimate answer; silence is not.** A parameter belonging to a component HTCondor mode does not run can be declared `Unsupported` with a reason, which is then reported to an operator who sets it. Of the nine object-typed parameters today, `Origin.Exports` is translated and the rest are explicitly unsupported.

Scalars need none of this: their translation derives from the name, so a new one is handled the moment it exists.

### 4.4 File locations follow the pool

Pelican's files go where an HTCondor administrator expects a daemon's files to be:

| Parameter               | Source                       | Why there                             |
| ----------------------- | ---------------------------- | ------------------------------------- |
| `Logging.LogLocation`   | `$(LOG)/PelicanLog`          | where daemon logs live                |
| `RuntimeDir`            | `$(RUN)/pelican`             | state that need not survive a restart |
| `*.DbLocation`          | `$(SPOOL)/pelican/…`         | state that must                       |
| `Cache.StorageLocation` | `$(LOCAL_DIR)/pelican-cache` | bulk storage, not spooled state       |
| `Server.Hostname`       | `$(FULL_HOSTNAME)`           | the pool's idea of this host          |

**These are defaults, not instructions, and the distinction is enforced.** An explicit `PELICAN_*` knob outranks Pelican's configuration files. A derived path is only a better guess than Pelican's built-in default, so it applies solely where the source tracker attributes the current value to `SourceDefault`. Treating derived paths as instructions would silently relocate files an operator had deliberately placed.

A knob that is unset or blank yields no value rather than a path rooted at nothing.

### 4.5 Provenance

Values from the pool are recorded against a `condor-config` source, with the knob that supplied them, so `pelican config dump` and the web UI report where a value came from. Precedence an operator cannot see is precedence they will eventually file a bug about.

## 5. Privilege model

HTCondor's credentials are readable only by root — the pool signing key, the system token directory, and the SSL host key are all root-owned and mode 0600 by design. A daemon that has dropped to `condor` still needs them.

### 5.1 The drop is reversible

Pelican's standalone drop is a permanent `setuid`; after it the process genuinely cannot regain root, which is a good property. HTCondor mode gives it up: the drop is `setresuid`, real uid stays 0, following HTCondor's `set_priv` model — the same thing every C++ daemon does for the same reason.

**Pelican's own drop must be actively disabled, not merely unused.** `config.isRootExec` is latched in the `config` package's `init()`, from `user.Current()`, before `main` and therefore before the framework drops. A daemon started as root keeps believing it is root regardless of its actual euid, so with `Server.DropPrivileges` set it would reach its own drop and perform a *permanent* setuid to a different account — destroying the re-elevation everything below depends on. `condor.Serve` forces the parameter false; an override rather than a validation error, because the latched flag means Pelican cannot evaluate the condition correctly itself.

### 5.2 The root window is per-thread, and one syscall wide

The naive implementation — switch the process to root, read, switch back — would be unacceptable. Go's process-wide credential calls affect every thread, so a process-wide root window elevates every concurrent goroutine, including cache handlers writing files on behalf of unauthenticated clients, and it would span network I/O of unbounded duration.

`droppriv` instead pins the goroutine with `runtime.LockOSThread` and elevates via `RawSyscall(SYS_SETRESUID)` — a **per-thread** transition. Concurrent goroutines on other threads are unaffected. The elevated region contains exactly one `open()`.

This is verified rather than argued: a privileged test drives credential reads on some threads while observers on others sample their own effective uid, and fails if any observes 0.

### 5.3 Credential acquisition is hoisted out of the connect path

CEDAR exposes credential-reading hooks that it calls synchronously; `htcondor.CredentialCache` implements them, reading through `droppriv.OpenAsRoot` and caching the bytes.

```
advertise loop (as condor)
  └─ CEDAR handshake
       └─ CredentialCache.ReadCredential(path)   ◄── cache hit: no elevation
            └─ LockOSThread; setresuid(0); open(); setresuid(condor); Unlock
```

The inversion is what makes this correct, not merely tidy. Wrapping the handshake instead would hold root across network I/O of unbounded duration, and — worse — any goroutine CEDAR spawned inside that window would run on a different, unpinned thread and *not* be elevated, producing failures that depend on library internals. **Never wrap network I/O, or anything that may spawn goroutines, in an elevation.**

Because bytes are cached, steady state costs zero elevations: one per credential per process, plus one per reconfigure.

### 5.4 Containing it

The process can regain root, which is a real threat-model change. Four things bound it:

1. **A narrow API.** No general `RunAsRoot(closure)`. The only privileged operations are reading a credential file and listing a credential directory.
1. **No attacker-influenced paths.** `readCredential` refuses any path that no HTCondor configuration knob named. The privileged operation is "read the file this knob names", not "read a file", and the refusal makes that mechanical rather than conventional.
1. **Observability.** Reads are counted per knob. Steady state is near zero, so an anomalous rate is a signal rather than something to reconstruct later.
1. **Mode gating.** The reversible drop is unreachable outside HTCondor mode.

### 5.5 Rotation

`condor_reconfig` flushes the credential cache, so the next read picks up a rotated key or renewed certificate — following HTCondor's convention that credential reload follows a reconfigure. Token *directory* listings are not cached, since their contents change as tokens are added and revoked.

### 5.6 The web certificate is a pool credential

`Server.TLSCertificateChain` and `Server.TLSKey` map onto `AUTH_SSL_SERVER_CERTFILE` and `AUTH_SSL_SERVER_KEYFILE`: one certificate per host, provisioned and rotated by the mechanism the site already runs.

Two properties of those knobs make this less direct than it looks. Each is a **comma-separated candidate list**, not a single path, and both carry **built-in defaults** naming files like `/etc/pki/tls/certs/localhost.crt` — so they are never unset, and "did the operator configure one?" cannot be answered by asking whether the knob has a value. Existence is therefore the test: the first candidate that exists wins, and both halves must be present. A host with a real pool credential gets it; a host with only the defaults keeps Pelican's own certificate, rather than having a working certificate replaced by one that cannot load.

The loader is installed through a seam in `web_ui` covering **both** the initial load and the periodic reload. Wiring only startup would work until the certificate was first renewed and then fail in production.

### 5.7 Platform support

Three layers, with different platform stories:

| Layer                         | Mechanism                                          | Platforms                                                                                             |
| ----------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Process-level reversible drop | `Setegid` + `Seteuid`                              | Linux by build tag; both syscalls exist on Darwin, so extending is a tag change and tests, not a port |
| Per-thread elevation          | `LockOSThread` + `RawSyscall(SETRESUID)`           | Linux only; Darwin has no `setresuid` per-thread semantics                                            |
| Privsep helper pool           | fork/exec as the target user, fds via `SCM_RIGHTS` | portable                                                                                              |

The middle layer is the one §5.2 depends on, so privileged behavior cannot be verified on macOS. `make condor-test-privileged` runs those tests as root in a container; as an unprivileged Linux user they skip with a stated reason, and on macOS they do not build. If macOS support is ever wanted, the privsep helper pool is the route, and the credential-reader interface already isolates the choice behind one package.

## 6. Collector advertisement

The framework supplies the loop: interval from `<SUBSYS>_UPDATE_INTERVAL`, a monotonic sequence number, `DAEMON_SHUTDOWN` evaluation against the outgoing ad, fan-out to every `COLLECTOR_HOST`, and INVALIDATE on exit so ads expire promptly instead of aging out. Pelican supplies its own attributes, projected from the data it already assembles for the director advertisement.

**One ad type, `PelicanServer`, not one per module.** Pelican deliberately runs several modules in one process, so a per-module type would either misrepresent a combined server or emit several ads describing the same process. `PelicanServerType` carries the enabled module set instead, sorted so an unchanged server does not produce a churning attribute.

Advertising starts only once the modules are running, so the first ad describes a server that is actually serving. Attributes are prefixed `Pelican*` to stay clear of HTCondor's namespace in a collector holding ads from every daemon in the pool, and `PelicanHealthStatus` reuses the rollup Pelican's own status API reports, so `condor_status` and the web UI cannot disagree.

## 7. Dependencies

The implementation lives in the Pelican repository and imports `github.com/bbockelm/golang-htcondor` directly, which transitively adds `github.com/bbockelm/cedar`. `github.com/PelicanPlatform/classad` is already in the Pelican organization.

Three externally-owned modules therefore sit on `pelican-server`'s critical build path. Mitigations worth keeping: pin exact versions, keep the HTCondor integration in packages a build tag can exclude, and treat the upstreams as projects to contribute to rather than frozen artifacts — a case in point being the configuration case-sensitivity bug found here and fixed upstream rather than patched around.

## 8. Testing

| Tier                              | Coverage                                                                                                                                                                                                                      |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit                              | Knob-name mapping; structured-parameter parsing; precedence and provenance; derived paths yielding to operator choices; DaemonCore argv parsing; local-name scoping; native-backend enforcement; ad construction.             |
| Integration, real `condor_master` | Startup under the master; logging to `$(LOG)`; the HTTPS port serving; a pool-configured parameter changing behavior; the ad reaching the collector; a targeted `condor_reconfig` handled; graceful shutdown on `condor_off`. |
| Privileged, Linux as root         | A root-owned 0600 credential readable after the drop; elevation confined to the reading thread; rotation picked up after a flush.                                                                                             |
| Standalone regression             | The existing federation suite unmodified, proving the listener and signal refactors did not disturb standalone behavior.                                                                                                      |

The integration tier needs no container: `golang-htcondor`'s harness stands up a mini pool in a temp directory and skips cleanly when `condor_master` is absent. Pelican's `pelican-test` image already ships HTCondor, so CI has it too.

Two notes on making these tests mean something. The daemon's stderr is captured to a file, because a failure before Pelican's log buffer is flushed otherwise leaves nothing at all — `condor_master` sends stdout and stderr to `/dev/null`, and the master reports only "exited with status 1". And the containment test records having observed the *dropped* uid, not merely the absence of 0: its probe returns -1 on syscall failure, which never equals 0, so without that it would have passed whether or not it ever read a real uid.

## 9. Open questions

1. **Ad schema stability.** Is the collector ad a committed interface or explicitly provisional? Consumers will assume committed unless told otherwise. Deferred until closer to a release.
1. **Naming conventions.** The `Pelican*` attribute prefix, and whether the advertised `Name` should follow HTCondor's `subsys@host` form.
1. **`condor_ping` against a non-standard subsystem.** It produced no diagnostic against this daemon and upstream's own tests do not use it; the command port is verified with a targeted `condor_reconfig` instead. Whether `condor_ping` can address `PELICAN` at all is unresolved.
1. **How much more of reconfigure should reload.** Today the runtime-configurable parameters do and the rest are reported. Extending that means making individual subsystems rebuildable, which is real work rather than a tidy-up.

## 10. Deployment

```condor
# /etc/condor/config.d/50-pelican.conf

PELICAN                = /usr/bin/pelican-server
PELICAN_LOG            = $(LOG)/PelicanLog
PELICAN_ADDRESS_FILE   = $(LOG)/.pelican_address
PELICAN_SERVER_MODULES = cache
PELICAN_PORT           = 8443

PELICAN_CACHE_ENABLEV2 = true

DAEMON_LIST    = $(DAEMON_LIST), PELICAN
DC_DAEMON_LIST = +PELICAN
```

`condor_restart -master` after installing; a `condor_reconfig` is not enough, because `DAEMON_LIST` is only consulted when daemons start.

## 11. Querying the transfer records with SQL

The transfer-record store (see [transfer-records-design.md](transfer-records-design.md)) is exposed over `dbrpc` on the same command port, so `htcondordb-cli` can run SQL against a Pelican daemon:

```console
$ htcondordb-cli -addr "$(cat /var/log/condor/.pelican_address)"
> .tables
> SELECT TransferPath, ReadBytes, UserDN FROM transfers WHERE Project == "cms" LIMIT 20
```

This works because the pieces already fit: `dbrpc.NewServerCatalog` takes the `*db.Catalog` the store already exposes, and the CLI accepts an arbitrary address, which the daemon already publishes.

**Two restrictions, both narrower than htcondordb's own service.**

*DAEMON only.* htcondordb registers the session at READ and escalates per connection. Here the whole surface is gated at DAEMON — the level HTCondor reserves for secret material — because the records name the object transferred, the address that asked for it, and the user who authenticated. A pool's READ list is usually far wider than its DAEMON list, and this data does not belong to everyone who may run `condor_status`.

*Read-only, unconditionally.* The store is the server's own record of what it served. There is no legitimate reason to write to it over CEDAR, and a mutation path would be a way to falsify accounting. Private attributes stay hidden for the same reason.

### 11.1 The authorization tables had to be installed

Registering a command at a level does nothing on its own. CEDAR's `Authorizer` is optional, and when nil it "advertises only the negotiated command (no authorization table applied)" — the levels passed to `Handle` are recorded and never consulted. Mounting the session at DAEMON without one would have been decoration: any peer that could authenticate at all could open it.

So the command port now installs `authz.Policy`, which resolves the pool's `ALLOW_`/`DENY_` tables the way HTCondor's `IpVerify` does. This also means the levels on the pre-existing `DC_*` commands — reconfigure and shutdown at ADMINISTRATOR — are enforced now, where before they were advisory.

### 11.2 Two access paths, two credentials

The change feed authenticates a federation token bearing `monitoring.raw`; this authenticates the pool's own CEDAR identity. That split is deliberate — the feed serves the federation, this serves the machine's operator — but it does mean two authorization systems reach the same data, and both have to be right. Anyone changing one should check the other still says what they think.

### 11.3 The store is resolved per connection

The command port is assembled before `LaunchModules` runs, so the store does not exist yet at registration time. Rather than reorder startup around an optional feature, the store is published when it opens and looked up when a session actually arrives; a session opened on a server with recording disabled is refused with that reason.
