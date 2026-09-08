# SCOPE Security Model

SCOPE is a security-workflow plugin, so its own privilege and trust boundaries are part of the feature.

## Design invariant

**The plugin must not weaken the Omarchy host in order to provide its feature.**

SCOPE v0.1 therefore does not request root privileges, modify firewall/network configuration, install packages, expose a listening service, scan targets, capture packets, store credentials, or execute imported content.

## Threat model

SCOPE treats these as untrusted input:

- engagement names and notes
- scope text until it has been parsed and normalized
- Nmap XML files and every string inside them
- hostnames and service names advertised by targets
- local state that may have been manually modified
- paths selected for import

The attacker model includes a hostile target deliberately returning strange service metadata and a local file being replaced with a symlink or oversized/corrupt content.

## Scope Guard

Scope rules support literal IPs, strict IP networks, exact hostnames, explicit wildcard hostnames, and exclusions.

- Exclusions always win.
- CIDRs use strict parsing. `10.10.11.42/24` is rejected instead of normalized to a broader `10.10.11.0/24`.
- An imported Nmap host is authorized from its literal IP only. Its advertised hostname cannot authorize that IP.
- Every SCOPE-generated HTTP/HTTPS action is checked again immediately before a URL is returned.
- Out-of-scope imports remain visible but are quarantined and non-actionable.

SCOPE does not claim to intercept actions performed in unrelated applications.

## XML import

The helper:

- opens imports with no-follow semantics where supported
- accepts regular files only
- caps input at 5 MiB
- rejects `DOCTYPE` and entity declarations before parsing
- caps host, port, hostname, service, and string counts/lengths
- imports only addresses, bounded hostname metadata, and open port/service names
- ignores Nmap script output in v0.1
- never shells out to Nmap or another scanner

## Process execution

The only subprocess created by the Python helper is a bounded, argument-array invocation of `/usr/bin/ip -j route get <literal-ip>` for Route Guard.

The QML surface may invoke:

- `scope-helper` with argument arrays
- `xdg-open <validated-http-or-https-url>` after Scope Guard approves the target
- `wl-copy <text>` for explicit copy actions

No user or imported string is concatenated into a shell command. Python uses no `shell=True`, `os.system`, or equivalent shell execution path.

## Route Guard

Route Guard is observational.

It can record a small baseline containing target, interface, gateway, and capture time. A later difference produces a warning. SCOPE never reconnects a VPN, changes a route, brings interfaces up/down, or changes DNS.

An unavailable or failed route query is `UNKNOWN`, never a green pass.

## State storage

State lives under `${XDG_STATE_HOME:-$HOME/.local/state}/omarchy-scope/`.

- directory: `0700`
- files: `0600`
- same-directory atomic replace for state writes
- advisory lock for mutations
- no-follow reads where available
- ownership and regular-file checks
- bounded JSON size

SCOPE stores sanitized engagement metadata only. It does not store packet captures, credentials, browser cookies, shell history, terminal input, or complete imported XML.

## No hidden monitoring

SCOPE does not read:

- shell history
- terminal keystrokes/output
- `/proc` to reconstruct user activity
- packet captures
- clipboard history
- browser sessions
- password stores

Its timeline records only explicit SCOPE events.

## Plugin-host limitation

Omarchy community plugins execute as unsandboxed user-level code inside the Omarchy shell. SCOPE minimizes what its own code does, but it cannot turn the shared plugin host into a security sandbox. Users should review SCOPE and every update before enabling it.

## Vulnerability reports

Please report vulnerabilities privately to the repository owner through GitHub private vulnerability reporting once the public repository is live. Avoid publishing proof-of-concept details that could expose users before a fix is available.
