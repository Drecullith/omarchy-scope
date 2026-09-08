# Development and Acceptance Plan

## Local tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile bin/scope-helper
```

No network access is required for the test suite.


## Static Quattro audit

The pre-render audit is intentionally separate from the real-machine gate. Current source has been checked against the Quattro contracts for `Panel`, `KeyboardPanel`, `PanelKeyCatcher`, the third-party `PluginBarApi` facade, shared controls, and current plugin manifest validation.

Static hardening in this pass includes:

- plain-text rendering for every built-in QML `Text` surface
- fixed `/usr/bin/xdg-open` and `/usr/bin/wl-copy` action paths
- active-engagement-only status polling
- compact vertical-bar rendering
- bar-level route/quarantine alert states
- long target-address elision
- responsive engagement-type layout
- state permission repair and absolute `XDG_STATE_HOME` enforcement
- evidence-preserving quarantine re-import behavior

This does **not** replace loading the plugin under a current Omarchy shell. QML type resolution, real geometry, font metrics, focus, drag/drop, and compositor behavior remain acceptance-test items below.

## Quattro integration gate

Do not call v0.1 stable until these checks pass on a current Omarchy Quattro machine.

### Installation and lifecycle

- Add plugin through `omarchy plugin add` and verify it lands disabled.
- Review and enable it on the built-in bar.
- Confirm the bar renders horizontally and vertically.
- Open/close from mouse and keyboard panel switching.
- Restart `omarchy-shell`; active engagement state returns without errors.
- Disable/remove plugin; no process remains running.
- Re-enable after removal/reinstall; existing optional XDG state is handled cleanly.

### Scope contract

- Exact IPv4 and IPv6 targets become in scope.
- CIDR members become in scope; non-members do not.
- Exclusions override matching positive rules.
- Hostname wildcard does not implicitly authorize the base domain.
- Host-bit CIDR such as `10.10.11.42/24` is rejected visibly.
- Malformed input never starts an engagement.

### Nmap import

- Drag/drop a valid XML file.
- Import a path through the field.
- Mixed scan visibly separates in-scope and quarantined targets.
- Quarantined targets have no actions.
- Re-import merges services rather than duplicating them.
- Malformed XML, symlink, oversized file, DTD/entity declaration, and non-Nmap XML fail visibly.
- A crafted hostname/service containing markup/control characters renders as inert text.

### Route Guard

- Start an exact-IP lab while a lab VPN route is active; baseline captures expected device.
- Drop/alter the route; panel changes to `CHANGED` rather than silently staying green.
- Restore route; panel returns to `match` against the original baseline.
- `TRUST CURRENT` changes the baseline only after explicit click.
- Missing `/usr/bin/ip` or route-query failure shows `UNKNOWN`.

### Actions

- HTTP/HTTPS service button opens only an in-scope target.
- Scope is checked at click time, not only at import time.
- Non-web service click only copies `target:port`.
- `xdg-open` receives one URL argument; no shell is involved.

### UI/polish

- No clipping at 1x, 1.25x, 1.5x, and 2x display scales.
- Long IPv6 addresses and hostnames elide/wrap cleanly.
- 0 targets, 1 target, many targets, and quarantine states are readable.
- Keyboard focus does not trigger shortcuts while typing.
- Panel follows theme changes live.
- Urgent/quarantine state is distinguishable without relying solely on color.
- Panel remains usable with a narrow/vertical bar.

### Performance

- No helper is left resident.
- Idle active engagement causes only the intended lightweight status refresh.
- Opening/closing panel repeatedly leaves no process leak.
- Large-but-allowed XML import stays bounded and does not freeze `omarchy-shell`.

## Marketplace gate

Before submission:

- update preview with a real screenshot/GIF-derived still from current Omarchy
- confirm globally unique plugin ID `io.github.drecullith.scope`
- run current marketplace validation/security baseline against exact commit
- fix every compatibility failure
- review any security capability reported by the baseline; target outcome is `passed`
- get explicit owner approval before creating the marketplace submission issue
