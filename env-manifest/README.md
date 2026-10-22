# Environment manifest

PowerShell inventory collector for emulator executable/PDB identity, explicit version/game/region/update/patch labels and declared local-baseline results. It records environment metadata; it does not run emulators, inspect game resources or establish interoperability.

From this repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./env-manifest/Collect-EnvironmentManifest.ps1 -Purpose tool_test -OutputPath output/example-manifest.json
```

Use `-CitraExePath`, `-YuzuExePath`, `-CitraPdbPath` and `-YuzuPdbPath` to inventory specific existing files. Labels default to `unknown`; baseline declarations accept `unknown`, `not_tested`, `passed` or `failed`. A declaration is supplied metadata, not an automatically performed game test. Inspect [the parameter block](Collect-EnvironmentManifest.ps1) for all options.

Output is constrained to this tool tree, defaults to `output/environment-manifest.json`, and refuses existing targets unless `-Force` is supplied. Keep machine-specific inventories private. [FREEZE-HASHES.txt](FREEZE-HASHES.txt) is a historical freeze record, not a current build manifest. Historical review copies and probe scripts live in [review-tools](../review-tools/README.md).

Updated 2026-10-22. Windows PowerShell 5.1 or later.
