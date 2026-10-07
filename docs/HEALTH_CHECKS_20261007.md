# Opt-in local health checks

`watchdog-health.py` supplements bounded systemd crash recovery with explicit
checks of a **currently running** service. It does not start inactive services,
automatically adopt an external watchdog, or enable its timer. Installation
alone does not activate checks. A successful process or local listener check
does not prove that an entire VPN route works.

Choose an installed long-running service and a probe that represents its local
contract. For example, use its known loopback SOCKS listener for a TCP check or
its own local health endpoint for HTTP. No listener port is created or changed.

```sh
python3 /usr/local/share/x-manager/scripts/watchdog-health.py report
python3 /usr/local/share/x-manager/scripts/watchdog-health.py set xray \
  --kind tcp --host 127.0.0.1 --port 10808 \
  --failures 3 --cooldown 300 --max-restarts 3
```

`--kind process` checks that the active unit has a live main PID. TCP also checks
that the selected loopback port accepts a connection. HTTP uses a local path and
requires a 2xx status. HTTP does not follow redirects, use proxy environment
variables, resolve DNS, or read the body. Only `127.0.0.1` or `::1` is accepted;
paths containing query strings, credentials or control characters are refused.
No failure of a remote website can trigger a restart through these probes.
`--max-restarts 0` records results without requesting restarts.

After reviewing the configuration and resolving ownership with any reported
external polling watchdog, the user can explicitly enable checks:

```sh
systemctl enable --now tuna-healthcheck.timer
```

The timer checks every 30 seconds, with five seconds of scheduling tolerance.
The default three consecutive failures therefore do not mean immediate
recovery. Each probe has a bounded 1–5 second timeout. The service as a whole
also has a 180-second timeout. Configuration and `set` never enable the timer.
Run `check` manually for an immediate check under the same safeguards.

Safeguards before restarting:

- The installation/rollback lock is available; a busy installer makes the
  entire run skip immediately. Concurrent health runs also skip.
- The selected unit is active and not masked; manual stop and permanent off
  from `service-control.py` inhibit it. Lifecycle commands are serialized with
  the final probe/restart decision.
- Known external polling watchdog services/timers are inactive. The checker
  reports conflicts and does not stop or disable those watchdogs.
- The failure threshold is reached, the cooldown elapsed and the saved restart
  allowance has not been spent. Healthy checks reset the failure streak only.
- The unit still has the same main PID and remains active immediately before
  the restart request. A recovered/replaced or manually stopped process is not
  restarted on an earlier probe result.

Each attempt is persisted **before** the restart command. A command failure,
process crash or reboot cannot silently replenish attempts. Changing or removing
and re-adding a check also does not replenish the allowance. After inspecting
the underlying fault, explicitly reset one unit:

```sh
python3 /usr/local/share/x-manager/scripts/watchdog-health.py reset xray
python3 /usr/local/share/x-manager/scripts/watchdog-health.py remove xray
systemctl disable --now tuna-healthcheck.timer
```

The last three commands are independent actions: reset replenishes the selected
allowance; remove deletes only that check; disabling the timer stops scheduling
all checks. None of them changes the selected service's off/on intent.

Configuration lives in `/etc/x-manager/healthcheck.json`, counters in
`/var/lib/x-manager/healthcheck/state.json`. The installer backs up configuration
but deliberately excludes these runtime counters from restore: an update or
rollback must not replenish the restart allowance. Only the explicit `reset`
command replenishes it. They use canonical allowlisted unit
names and contain no credentials. An invalid state fails explicitly instead of
resetting counters. `report` is read-only. Check results go to the systemd
journal as structured JSON, including skipped, unhealthy, cooldown, exhausted,
restarted and failed-restart reasons. Systemd's existing per-service crash
recovery remains responsible for inactive/crashed services; this module only
requests restarts for opted-in active services that fail their local contract.

Local tests cover lifecycle inhibition, masks, external-watcher races, PID
changes, maintenance locking, failure thresholds, cooldown, persistent limits,
failed restarts, explicit reset, monitor-only mode, configuration validation,
read-only reports, and real disposable loopback TCP/HTTP probes. Production
acceptance and service-specific useful endpoint selection remain separate.
