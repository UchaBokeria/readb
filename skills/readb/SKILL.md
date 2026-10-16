---
name: readb
description: Access remote Android phones and Quest headsets through the readb coordinator, with shared viewers and one controller per device.
---
<!-- managed-by: readb -->

Use the configured server. On a client, never fall back to direct ADB/USB, guess
ports, change VPNs or clear pairing. Server-local use requires explicit `--local`.
Routine owner-authorized status, screenshots, logs, installs and UI tests proceed
within the active task scope. Honor project coordination and existing jobs.

1. `readb context inspect`; `readb device ls`; select the exact device ID.
2. `readb --device ID device inspect` and `readb doctor` need no ticket.
   For device commands, claim with actual identity:
   `readb --device ID job claim --agent TOOL --origin HOST --session SESSION --job PURPOSE --mode view`
   Use `--mode control` for input, installs, transfers or other changes.
3. Read `ticket_path` from the JSON reply. It is private on the invoking host.
   Pass `--device ID --ticket FILE` on each command. Never print its token.
4. Example: `readb --device ID --ticket FILE action run model`.
   Screenshot: `readb --device ID --ticket FILE action run screenshot > capture.png`.
   For input prefer typed actions: `action run tap -- X Y`. See `action ls`/`--help`.
5. Default lease90s: run `job heartbeat` every30s while reviewing; an expired
   ticket needs a new claim. Release with `job release` after cleanup. Do not
   share tickets across agents. Use separate tickets for concurrent viewers.

Viewers can share screenshots/logs/read profiles while one controller works.
Only that controller drives UI. Different devices can run independently. Busy
names the holder/host/job: report it, wait or coordinate; never bypass it. Unknown
cleanup stays blocked until evidence-based reconciliation. A dropped connection
is not proof a remote mutation stopped. Inspect before retrying.

Paths for pull/push/install refer to the server. Binary stdout redirects locally.
Use `logs -f`, `history`, `ps`, `doctor` for diagnosis. Awake is not unlocked;
protected boot unlock/consent can still require normal OS interaction. Preserve
PIN, private data and unrelated peers. Never expose pairing codes or credentials.
