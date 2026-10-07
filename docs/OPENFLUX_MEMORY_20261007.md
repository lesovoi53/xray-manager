# OpenFlux memory: local diagnosis and candidate, 2026-10-07

## Evidence boundary

The parent task obtained a read-only snapshot of the existing Debian 13 host.
Four OpenFlux channels had aggregate RSS **291.37 MiB**, aggregate current cgroup
memory **314.74 MiB**, no process swap, and effective `GOMEMLIMIT=150MiB` each.
Their aggregate virtual address space was about **6.30 GiB**; that is a different
measurement from resident RAM. The snapshot did not reproduce the earlier
reported 3 GiB incident. No historical OOM was present in the selected kernel
journal window, which does not establish that an earlier incident never occurred.

The deployed binary hash matched the local previously rebuilt release binary:
`6915d0da6fa7eda0041c51528239746e67f68ac6c3cd25def11562b9287fbb5b`.
Its published source archive remains pinned to
`6ade7a1b7cd415edf829351eb8479f697813b546fd58fc499482167006112cbe`.
The original upstream revision remains `d13aa5b701c8ee5311aa638de16c70ea094d9dfd`
with the existing multistream/Boards/Volga patches. No existing transport patch
or upstream pin was replaced.

## Reproduced defect and narrow fix

`tests/openflux_cupsonline_memory_test.go` calls the actual
`CupsonlineTransport.Send` method. Four one-packet queues replace WebSocket egress
and are drained immediately. No network, service, credential, sleep, or large
packet queue is involved. The test verifies the existing flow hash selects the
same channel and the packet bytes remain unchanged.

After a warmup and garbage collection:

| Scenario | Original source | Candidate |
|---|---:|---:|
| 200,000 sends of the same flow | No retained growth | No retained growth |
| 200,000 additional unique flows | 10,194,752–10,228,864 bytes retained | 2,688 bytes retained |
| Unique-flow assertion, maximum 1 MiB | FAIL twice | PASS three times |

The hypotheses were a persistent flow cache, retained test/egress queues, or
temporary hash allocations. The repeated-flow control and drained queues
exclude the second explanation; collection excludes transient allocations.
Source inspection then confirmed that a map kept every flow tuple permanently.
It held a channel index that was already derivable from the unchanged hash and
a sequence counter that was never transmitted or read. The debug statistics
also read the map length without the writer's lock.

`patches/openflux-memory.patch` removes this redundant cache and its lifetime
unique-flow debug counters. Transmission, receive, reconnect, and connection
statistics remain. Channel membership is fixed after start, so calculating the
same hash on each send preserves flow affinity and the existing wire format.
No URL, routing decision, subscription, key, or port is changed. A bounded scan
of Boards and Mail.ru transport state found no equivalent persistent per-flow
map; that is not a general proof that those transports cannot retain memory.

This fixes a demonstrated Cupsonline retention mechanism. It does **not** prove
that the historical 3 GiB report had this cause, or that all possible OpenFlux
memory problems are resolved.

## Reproduction and build

Use Go **1.26.4**, the verified source archive, and a separate extraction folder.
Copy `tests/openflux_cupsonline_memory_test.go` into the extracted
`openflux/transport/cupsonline/memory_retention_test.go`, then run:

```sh
go test ./transport/cupsonline -run TestCupsonlineFlowChurnRetainedMemory -count=1 -v
```

It fails on the published source and passes after the new patch. The archive
has CRLF in the affected source file; normalize that file's line endings before
strict patch application. `scripts/build-openflux.sh` does this only in its
temporary, hash-verified extraction, applies the patch with `--fuzz=0`, installs
the regression, runs `go test ./...`, and builds the binary plus Volga checker.
All Go packages passed in the local offline candidate build.

Memory-only candidate binary SHA-256 (superseded by the restart-room fix below):
`7c28a64021e9e1b13e57fb7bb19340f7f18d1f216df41bc1665804b128adcd26`.
The checker hash stayed
`c67bff2bd55d6de9738a1111c2888b999eed3bedb639c4d5ba596d8674951b6f`.
The separate source review archive already includes the memory patch: it must
not replace the pinned build input without revising the patching contract.

## Independent Cupsonline restart-room defect

The authorized client acceptance test subsequently found that Cups could not
carry HTTPS while Mail.ru and other tested transports could. The parent task's
read-only comparison on the test VPS found four configured room identities,
15 room identities created across the observed journal window, and **zero**
identities shared between the configured and generated sets. The user separately
reported that only one supplied Cups room remained live. No room identifier or
link is retained in this report.

This defect predates the memory patch. `NewCupsonlineTransport` returned before
parsing `rawURL` whenever `isClient` was false. `Start` also selected room creation
solely from `isClient`. Consequently an explicitly configured exit ignored its
rooms and created new ones after each process restart, independently of the
configured client subscription. Setting the exit's `isClient` to true is not the
fix: room selection and transport direction are separate concerns.

`patches/openflux-cupsonline-rooms.patch`, applied after the memory patch, parses
explicit room identities for either role and joins precisely those rooms. It
preserves `isClient`, validates UUIDs and duplicate identities before HTTP,
rejects a different room returned by the server, and fails the complete explicit
set if any join fails. A partial set would change flow-hash modulo membership
between peers. It never falls back to room creation for invalid or unavailable
explicit configuration. An empty exit URL retains legacy room creation.

`tests/openflux_cupsonline_rooms_test.go` drives the real constructor, `Start`,
HTTP authorization and `RoomUUIDs` with an intercepted HTTP transport and an
unsupported WebSocket scheme (no external network). Before the fix, the test
observed the exit change fixture room A into new room B, invalid explicit
configuration perform HTTP, and replacement identities be accepted. After the
fix, single-room, packed-URL and raw-packed forms survive two simulated process
restarts for both roles; malformed/duplicate inputs, replacement rooms and
partial sets fail closed; empty-exit compatibility passes. The full Go suite
and race-enabled Cups memory/room regressions passed.

The intermediate local binary includes both Cups patches, built with Go 1.26.4 from
the unchanged hash-verified source archive through `scripts/build-openflux.sh`:

`6c282afc6087293c7d70b3a7b1b3249bc09b900c1a10c5c67ced87526c5a4974`.

The Volga checker remains
`c67bff2bd55d6de9738a1111c2888b999eed3bedb639c4d5ba596d8674951b6f`.
This does not revive expired rooms. An existing set containing expired rooms
will fail safely and needs an explicitly approved configuration/subscription
change; the source fix itself changes neither saved links nor credentials.

Boards is independent: neither Cups patch modifies its source. The pinned
Boards transport explicitly supports multiple documents, and Socket.IO or
dashboard subscription handshake failures precede codec/encryption processing.
A successful HTML page fetch alone cannot establish document access; the
separate read-only diagnostic checks guest-token and metadata presence without
joining a WebSocket, writing board objects, or bypassing CAPTCHA.

## Boards Engine.IO v4 heartbeat direction

Subsequent parent-owned read-only checks found all four configured Boards
documents accessible through guest authentication and metadata. The selected
journal contained 88 handshake-to-close pairs at 20.021–20.423 seconds (median
20.049 seconds). Pairing used same-process FIFO matching and is a timing
heuristic, not an individual socket identifier. This aligns with the pinned
transport's 20-second unsolicited Engine.IO ping timer.

The transport requests `EIO=4`, but its `pingLoop` sent raw `2` from the client.
Engine.IO v4 specifies server-initiated ping `2` and client pong `3`; its v4
history explicitly records the reversal from earlier versions. See the
[official heartbeat specification](https://github.com/socketio/engine.io-protocol#heartbeat).
This is independent of the dashboard application-layer heartbeat event.

`tests/openflux_boards_heartbeat_test.go` exercises the actual
`BoardsTransport.connectAndServe` against a loopback TLS/WebSocket fixture. It
performs the Engine.IO/Socket.IO/dashboard handshake, sends server ping and a
packet, checks client pong and both data directions, observes the dashboard
heartbeat, and rejects unsolicited client ping. It runs beyond the real
20-second production interval, without altering timers or bypassing TLS
verification. Only the fixture certificate is trusted by the test process.

- Original Boards source: FAIL after **20.02 seconds**, reporting unsolicited
  client ping `2` after otherwise successful handshake and data exchange.
- `patches/openflux-boards-heartbeat.patch`: removes only the unsolicited ping
  goroutine/function and corrects the interval comment. Server `2` → client `3`,
  the dashboard heartbeat, and the existing 90-second read deadline remain.
- Full Go suite: PASS, including the real heartbeat regression. The same
  regression with the race detector: PASS after **21.01 seconds** observation.

The final local candidate contains all three strict patches, built from the
unchanged original archive with Go 1.26.4:

- OpenFlux SHA-256:
  `794de52f154a5499db70b0f2c45e840887db7015ef9bde87fad3641dca2cb95d`.
- Volga checker SHA-256 (shared Yandex package also changed):
  `62a74138e8c63b439139c9d73e547d983ee0aa7d14c4b7e70db7d5696fb8a1f9`.

Deployment, Android end-to-end acceptance, and long-duration live stability
remain parent-owned checks. This local regression demonstrates and fixes the
specific heartbeat-direction defect, not every possible Boards failure.

## Resource management

`scripts/openflux-resources.py` defaults to a read-only report. It reports host
RAM, available memory, swap, visible cgroup-v2 memory ceilings, configured and
running channels, saved budgets, actual process `GOMEMLIMIT`, RSS, virtual
memory, and current/peak cgroup memory where available. Unavailable runtime data
is labelled unknown. It never executes channel settings or emits URLs/keys.

Capacity policy, explicitly an estimate:

- Use the smaller of physical RAM and visible cgroup limits. Do not count swap.
- Reserve at least 256 MiB or 20% for the OS, and at least 256 MiB or 15% for
  other services, including Xray, panels, DNS and other tunnel processes.
- Keep 25% of the remaining capacity outside the aggregate Go soft budget.
- Divide the aggregate capacity across configured, active, and previously
  managed channels. Preserve lower existing targets by default. More free RAM
  alone does not justify increasing an already functioning target.
- Refuse an apply below 64 MiB per channel; advise reviewing measured reserves,
  channel count, or hardware. This is a policy guard, not a measured universal
  minimum requirement for every transport.

Reserves and the aggregate target can be tuned explicitly:

```sh
python3 /usr/local/share/x-manager/scripts/openflux-resources.py report
python3 /usr/local/share/x-manager/scripts/openflux-resources.py plan --json
python3 /usr/local/share/x-manager/scripts/openflux-resources.py plan \
  --total-mib 600 --reserve-os-mib 768 --reserve-other-mib 768
```

`--total-mib` is the aggregate **Go** target, not a per-channel RSS allowance.
`GOMEMLIMIT` remains a soft runtime target; it cannot collect live application
state or guarantee a process/host memory ceiling. No arbitrary hard cgroup cap
is introduced. Recommendations are reviewable estimates, not throughput claims.

Explicit `apply` accepts the same options and atomically writes only
`/etc/openflux/resources.conf`, for example `1=150MiB`. The runner parses this
strict numeric data after the existing channel settings without `source` or
`eval`. The installer now calls `auto` before starting configured channels, and
`openflux@.service` calls it from a privileged `ExecStartPre` before the runner.
With no resource file, `auto` creates an automatic budget. Subsequent starts
recalculate automatic budgets under a shared file lock; unchanged budgets do not
produce duplicate snapshots. Files without the automatic header are treated as
manual choices and preserved byte for byte. Explicit `apply` selects manual mode.
Invalid files, unavailable systemd inspection, or less than the minimum safe
allocation fail before the exit binary starts, without replacing the old budget.

Every resource command leaves running processes untouched; a saved target
becomes effective on the channel's next start. Reports show pending changes
beside the actual running Go limit. Under automatic management newly configured
channels enter the shared calculation at startup. Under manual management a new
channel outside the saved budget is refused until explicitly included. Existing
lower targets and reservations for previously managed channels are preserved.
A reduced saved budget does not reduce already-running processes' targets:
controlled restarts are required if the intended aggregate must hold immediately.
No hot reconfiguration of Go's memory limit is claimed.

Apply returns a snapshot ID. `rollback ID` restores the exact previous managed
file (or removes only the new managed file if none existed). Snapshots are kept
under `/var/lib/x-manager/openflux-resources`; path traversal and symlink targets
are refused. Apply/rollback share a file lock, and stale plans or rollback over
newer edits are refused. Snapshots do not contain channel secrets. This is a
transaction for this one managed file, not a general server rollback or a
guarantee against power loss. It does not restart services.

Linux unit/runner tests cover 40 RAM/channel combinations, cgroup parent limits,
no-secret read-only reporting, empty drafts, active/stopped channel accounting,
budget overrides, current-target preservation, repeat/update/rollback,
simulated write failure, stale plans, newer edits, symlink refusal, and rejection
of shell expressions in the data file. VPS deployment, long-duration load, and
Android acceptance are separate from these local checks.


## Automatic budgeting and readable diagnostics acceptance, 2026-10-07

- Local Python/runner/menu regressions: 57 tests passed (21 resources, 28 service
  control/menu, 3 watchdog presentation, 5 main-menu navigation).
- Native systemd in isolated Debian 13: 5 cases passed through the real runner
  and an isolated fake exit binary. A privileged pre-start helper prepares the
  budget for an unprivileged runner; 114 MiB takes effect; a repeat is unchanged;
  a manual 100 MiB choice wins; insufficient RAM blocks startup and preserves
  the previous resource file. This is not an OpenFlux network-throughput test.
- Authorized test VPS 109.237.98.220: installed only the resource helper, menu,
  service-control presentation, and the pre-start hook in the existing unit.
  Backup: `/var/backups/ram-menu-bcvqp0at`.
- Automatic saved budget on its 967 MiB capacity: channels 1/2/3 receive
  114/114/113 MiB. Repeated `auto` changed nothing. The effective systemd hook
  was checked after daemon-reload. No service restart was performed.
- Existing processes still report 150 MiB. The report explicitly distinguishes
  those current values from saved budgets pending their next starts.
- Service PIDs/states, channel configurations, shared watchdog configuration,
  and stop/off markers were unchanged. User-stopped TUNA remained stopped.
- Empty watchdog conflicts now display `Конфликтов watchdog нет.`; the JSON CLI
  remains unchanged for callers that omit `--human`.
- The full installer was not rerun on the VPS in this narrow update. Network
  traffic, long-duration load, and client connectivity were not retested here.
  No GitHub commit, push, or release was made for these changes.

The resource snapshot for this VPS change is
`30416349-7213-4996-81da-403da7b52d22`. To restore it while the current managed
file is unchanged, use `openflux-resources.py rollback ID`. Because the startup
hook recreates automatic budgets, a persistent rollback of automatic management
also requires restoring the previous unit and helper from the private deployment
backup and running `systemctl daemon-reload`. Do not restart services merely to
restore these files; running processes have not been altered. Full file mappings
are in the backup's `manifest.json`.
