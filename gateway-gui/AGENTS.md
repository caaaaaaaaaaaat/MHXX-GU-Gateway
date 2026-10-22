# Desktop release conventions

For every Windows desktop build or release task, follow [RELEASE-WORKFLOW.md](RELEASE-WORKFLOW.md).

Use the V335 layout: exactly EXE + `使用说明.md` in `XXGU-Gateway-Vxxx-release-win64.zip`, with license text embedded in the guide; publish matching sources separately as `XXGU-Gateway-Vxxx-source.zip`. Keep version-specific release notes in `releases/Vxxx.md`. The build script generates and verifies these artifacts automatically. Do not substitute the internal build directory ZIP or an ad hoc user ZIP for the official release package.
