# Home SIEM Lab — Detection Engineering on the Elastic Stack

An end-to-end SIEM built from scratch to practice the core analyst loop: collect logs, establish a normal baseline, generate attacks, write detections, and catch a brute-force attempt — building and debugging every layer by hand.

## Objective
Build a working SIEM to practice log collection, detection engineering, and the triage reasoning that separates real attacks from everyday noise.

## Architecture
- **SIEM VM (Ubuntu Server):** Elasticsearch + Kibana
- **Log-source VM (Ubuntu Server):** generates activity to monitor
- **Networking:** NAT for updates, host-only planned for isolation

## Build Log

### VM Setup
Two Ubuntu Server VMs, one job each. I went with Server instead of Desktop because that's how the real thing runs — production log servers are headless. No GUI eating up RAM that the log stack needs, less installed means less attack surface, and it forced me to do everything from the command line, which is the actual skill for managing these. The graphical side comes from Kibana's web console later, not from a desktop sitting on the server.

The clone didn't go clean, so I didn't fight it. I botched something in the second VM's install, and instead of burning an hour debugging a machine I was going to throw away anyway, I just deleted it and built a fresh one. That's the whole point of working in VMs — they're disposable, so rebuilding beats debugging when the box doesn't matter yet. Then I confirmed each VM had its own IP so they wouldn't step on each other.

### SIEM Setup (Elasticsearch + Kibana)
Installed SSH first for sanity. The VMware console has no copy-paste and it's cramped, so I put `openssh-server` on the SIEM box and connected from my host terminal. That's also how real servers get administered, so it's a rep worth having either way.

Elasticsearch + Kibana on the SIEM VM, both from Elastic's apt repo (9.4.4). Elasticsearch throws its security setup and the `elastic` user password on install — grabbed that with the reset-password tool and saved it host-side. Note: lab creds live in a plaintext notes file for convenience; production would use a secrets manager, not this.

Kibana wouldn't load over HTTPS. The browser kept throwing a secure-connection error until I realized Kibana was serving its front end over plain HTTP, not HTTPS — so forcing `https` was dropping the connection. Hit it on `http` and it loaded. Worth flagging that a real deployment would put TLS on Kibana or a reverse proxy in front of it; running it on HTTP is a lab shortcut, not something you'd ship.

### Shipping Logs (Filebeat)
Put Filebeat on the log-source VM to forward its logs into the SIEM. This is where most of the debugging happened, and honestly it was the most useful part:

- **Service kept crash-looping** after setup ran fine. `journalctl` pinned it — the `system` module was enabled but had no filesets turned on, a default that shifted on Ubuntu 26.04. Enabled `auth` and `syslog` in the module config and it came up.
- **Output failed with an EOF error.** Same root cause as the Kibana issue but flipped — Filebeat was trying to reach Elasticsearch over `http`, but Elasticsearch (unlike Kibana) requires `https`. Switched the output to `https` and disabled cert verification for the self-signed lab cert. Good lesson: on the same box, Kibana's browser side runs HTTP while Elasticsearch's API runs HTTPS — two services, two protocols.
- **Index existed but was empty** (`docs.count` 0). Pipeline was plumbed but nothing was flowing yet. Restarted Filebeat, generated some events, and the count jumped to ~2,850 — logs were in.

### Proving It Works
Generated real auth events and hunted them down in Kibana:

- **Failed logins** — SSH'd into the log-source VM with wrong passwords. Showed up as `event.dataset: system.auth`, `event.outcome: failure`, with the source IP, the fake username, and the method. That's a real security event — if that IP were unknown and hammering usernames, that's the alert you'd triage.
- **Successful login** — logged in clean; showed up as the same `ssh_login` action but `event.outcome: success`, from a different source IP, and carrying an extra session category the failures don't have. One action, more downstream events — a reminder that counting events isn't the same as counting actions.
- **The false-positive lesson, in real data.** The failed and successful logins are the same event type, differing mainly on one field (`event.outcome`). A detection that fires on `ssh_login` alone would flag every legitimate login I make — a false-positive factory. Keying on repeated failures from one source IP in a short window is what separates an actual brute-force attempt from a fat-fingered password. Seeing that in events I generated myself made the concept click in a way reading about it never did.

### Building a Baseline (benign event generator)
Before writing detections, I wanted a steady stream of normal activity in the SIEM — because the hard part of detection isn't catching the bad thing, it's not tripping on the fifty legit things that look like it.

Set up cron jobs on the log-source VM to fire benign activity on a schedule — mainly `sudo /bin/true` every few minutes, which throws a real sudo event without doing anything. Sudo is exactly what an attacker uses for privilege escalation, so having benign sudo firing constantly is what teaches you to tell normal admin activity from suspicious.

For the cron sudo to run without a password prompt, I added a `NOPASSWD` rule — but scoped it to only `/bin/true`, nothing else. Least privilege even in a lab; I didn't want a blanket password-less sudo sitting around.

Lesson that bit me: one sudo action produces ~3 near-simultaneous log lines — the command itself, plus PAM opening and closing a session. Saw three entries within milliseconds of each other and had to figure out why. This matters for detection: if you write a threshold rule that counts raw log lines, that 3x multiplication makes it fire way too early. You have to count the action, not the log line.

### Attack Generator (negative events)
Built a script to generate failed SSH logins on demand — the exact events a brute-force detection needs to catch. Used `sshpass` to feed wrong passwords non-interactively, looping six failed attempts a couple seconds apart.

Key design decision: run it from a different machine (VM1) aimed at the log-source VM, not on the box against itself. The thing you're detecting is defined by where your sensor is — the monitored box has to be the target so its auth log records the attempts, and the attack needs a real source IP from somewhere else. Same/same IP would be unrealistic and would muddy the field a brute-force rule keys on.

Debugging this taught me more than the setup did. Ran into a stretch where the script did nothing, silently — no errors, nothing in `auth.log`. Worked through it methodically: a manual login attempt succeeded and showed in `auth.log`, but the script didn't — so the problem was in the script, not SSH or the network. Turned out to be a missing `$` on the target variable (`baduser@TARGET` instead of `baduser@$TARGET`), so every attempt was trying to reach a host literally named "TARGET" and failing to resolve. What made it hard to see: I'd piped errors to `/dev/null` to keep the script quiet, which also hid the "could not resolve hostname" message that would've told me instantly. Lesson: don't suppress stderr while you're still debugging — the thing you're hiding is usually the thing you need to see.

(Also lost some time earlier to the target VM's DHCP-assigned IP — worth pinning a static IP so the monitored host stays addressable and scripts/rules don't silently break on reboot.)

### Detection Rules
This is where it goes from "collecting logs" to actually detecting.

**Encryption key gotcha first:** the detection engine wouldn't let me create rules until I generated an encryption key for saved objects (`kibana-encryption-keys`) and added it to the Kibana config. One-time setup for a self-managed install. Production would source those keys from a secrets store, not plaintext yml.

**First rule — sudo usage (custom query).** Started simple to confirm the whole rules-and-alerts pipeline works: a custom query rule matching `process.name : "sudo"`. Since the cron baseline fires sudo every few minutes, this generated alerts on its own within minutes. Walk before run — confirming the simple case works means that if a harder rule doesn't fire later, I know it's the rule logic, not the plumbing.

**Real rule — brute-force SSH (threshold).** A threshold rule: alert when there are 5+ failed logins from the same source IP in a short window. This is the detection that matters, because it's built to tell an attack from an accident — a burst of failures from one source is brute-force; a single failed login is someone fat-fingering a password. Keying on the count-per-source is what separates the two.

Ran the attack script (6 failures from one IP, over the threshold) → the rule fired and the alert landed in the queue. Working brute-force detection, end to end.

## Where It Stands
Complete detection loop, end to end: log-source VM → Filebeat → Elasticsearch → Kibana. A benign baseline, an on-demand attack generator, and a threshold rule that catches a brute-force burst — real auth telemetry flowing, and I can tell good logins from bad in the data. Built and debugged every layer myself.
