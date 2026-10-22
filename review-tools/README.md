# Review tools

Historical independent probes and review fixtures. This directory is not a production runtime dependency or the primary build/test entry point. Start with each module's README for supported checks.

| Directory | Purpose |
| --- | --- |
| [m1](m1) | Independent room-client codec/session review and re-verification probes |
| [g3](g3) | Citra/Yuzu source-layout and codec probes, with local shim headers |
| [env-manifest](env-manifest) | Historical manifest collector copy, path-boundary probes and fixtures |

Prefer the maintained [env-manifest collector](../env-manifest/README.md) for new inventories. Files below `probes/` and recorded result JSON describe historical runs and may contain machine-specific paths. They are not current acceptance reports. Review scripts can require the full engineering workspace, upstream snapshots and the original toolchain layout; inspect their parameters and paths before invoking them.

The current player-facing application is [gateway-gui](../gateway-gui/README.md); current core acceptance is summarized in [citra-gateway](../citra-gateway/README.md).

Updated 2026-10-22.
