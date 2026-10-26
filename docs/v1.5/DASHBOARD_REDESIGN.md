# v1.5 Dashboard Redesign

The redesign keeps the six existing destinations and preserves all current data and controls. It reduces repeated presentation without deleting underlying monitoring or security capability.

## Shared system

- Keep the navy palette, restrained cyan/teal accents, typography and current responsive navigation.
- Use one page heading and consistent section spacing, controls, focus indicators and empty states. Keep version/build information in one shared location only.
- Prefer compact status rows and progressive disclosure over nested cards. Retain visible labels, keyboard operation, focus indication, screen-reader names and reduced-motion behavior.
- Preserve mobile navigation, scroll behavior, forms and tables at 320 px and desktop widths. Validate contrast for text, status colors and focus on dark surfaces.

## Page structure

| Destination | Proposed default view | Details retained on demand |
| --- | --- | --- |
| Overview | One overall system state, one security-protection state, and only actionable problems. Normal operation is a short quiet summary with links to Health or Security. | Component evidence stays on Health; security counts and events stay on Security. Remove the 12-component grid and duplicated security statistics. |
| Statistics | Proxy request/allow/block/error and inbound/outbound traffic, with one range selector and compact metrics. Clearly label live interval values versus cumulative counters. | Historical range and data access remain. Charts gain unit/time axes, readable scales and synchronized hover/focus time; concise tooltips expose sample values. Host CPU/memory charts move to Health. |
| Health | Compact system/path summary and host CPU/memory, followed by concise component rows. Preserve Caddy → WireGuard → Windows → Jellyfin ordering. | Expand a component for last checked/freshness, evidence and diagnostics. Keep original health-event records while grouping repeated transitions for display if evidence supports it. |
| Access Control | Keep default-deny, IPv4/IPv6/CIDR input, friendly names, edit and remove. Standardize the address/name form and row actions. | Existing validation and per-entry actions remain. |
| WireGuard | Compact tunnel state, latest handshake and combined sent/received counters. Keep peer regeneration visually separate and clearly destructive. | Retain configuration recovery/download, connection evidence and detailed diagnostics. A handshake must not imply Jellyfin reachability. |
| Security | Put password and TOTP controls together under account security. Make protection state, failed logins and current bans immediately scannable; retain history charts/events and all current filters. | Collapse rarely changed SSH/admin protection policies and detailed event diagnostics. Provide a useful zero-data state without giant blank charts. |

## Interaction and accessibility decisions

- Keep the current server-driven authorization and confirmation requirements for password/TOTP, whitelist changes, policy changes and peer revocation.
- Use existing React/browser tooling for keyboard traversal, focus-visible, form labels, table relationships, empty-state announcements, responsive screenshots and reduced-motion behavior. Add targeted tests for errors and unavailable data. Avoid a new runtime dependency.
- Review measured text/focus contrast against the shared dark palette. Verify each graph has an accessible text equivalent and keyboard-readable values; color is not the sole status signal.
- Preserve fallback HTML templates and apply equivalent security-critical form behavior to both frontend paths.

## Verification and risk

The baseline Chromium TOTP security screenshot varied in height (expected 3241 px, rendered 3287 px). The candidate test setup fixes the visible security-history viewport height before screenshot capture; the resulting images were inspected and ordinary three-browser screenshot comparison passed.

## Candidate implementation and remaining review

The candidate implements a compact Overview with system/security states and
actionable issues; proxy-only Statistics with live/cumulative distinctions,
shared historical selection, and clearer chart axes; host CPU/memory and
expandable evidence on Health; and a less repetitive Security presentation.
The transport-status badges and the "Rarely changed" policy label are removed;
Health rows place component states in a consistent column at mobile and desktop
widths. Peer handshake and traffic details are refreshed through the existing
health event stream while the page remains open.
Access Control retains the existing default-deny, CIDR and friendly-name
controls. WireGuard keeps its peer controls and now submits the one-time
configuration request as an authenticated CSRF-protected POST. The six routes
remain present. The normal Chromium/Firefox/WebKit desktop/mobile browser suite
and screenshot comparisons passed in the local release gate.

The design acceptance checklist is not fully closed: keyboard/focus traversal,
contrast measurements, screen-reader/chart equivalents, reduced-motion
behavior and formal empty/error-state accessibility review remain pending.
The screenshot setup limits the history list only for stable image capture;
the production history retains its normal scroll behavior.
