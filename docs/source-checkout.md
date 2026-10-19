# Run REA from a source checkout

A checkout is not an installed REA package. It contains neither compiled runtime
files nor the Windows native addon. Use the Node version in `.nvmrc` and the npm
version in `package.json#packageManager`.

Clone without recursive submodules:

```sh
git clone --no-recurse-submodules git@github.com:lcxFZAC/rea.git
cd rea
npm ci
```

The Unblob test corpus contains names Windows cannot check out. Core CLI/MCP and
Ghidra do not require it. Do not disable Git path protection to clone the corpus;
initialize only a provider's required submodule on its supported host.

## Windows x64 prerequisite, before building

The build supervisor itself uses the Windows native addon. Follow
[native artifact recovery](../native/windows/README.md#restore-the-artifact-in-a-source-checkout)
before `build:cached`, not only before native analysis. In PowerShell, an explicit
recovery from the exact published version is:

```powershell
$version = (Get-Content package.json -Raw | ConvertFrom-Json).version
$staging = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory $staging | Out-Null
npm pack "rea-agents@$version" --pack-destination $staging
if ($LASTEXITCODE -ne 0) { throw 'Package acquisition failed' }
tar -xzf "$staging/rea-agents-$version.tgz" -C $staging package/native/windows/build
if ($LASTEXITCODE -ne 0) { throw 'Artifact extraction failed' }
# Preserve any existing build directory before replacing either file.
if (Test-Path native/windows/build) {
  Move-Item native/windows/build "$staging/previous-build"
}
New-Item -ItemType Directory -Force native/windows/build | Out-Null
Copy-Item "$staging/package/native/windows/build/*" native/windows/build/
node scripts/verify-windows-native-artifact.mjs
if ($LASTEXITCODE -ne 0) { throw 'Artifact verification failed; do not build' }
```

This is an operator-requested download, not an automatic `rea setup` action.
If native sources changed or this version is unpublished, build the addon from
this revision using the Linux/MinGW lane instead. CI does that for every revision;
copying a published addon does not verify changed native sources.

## Build and prove both entrypoints

```sh
npm run build:cached
npm run verify:source-runtime
node scripts/rea.mjs mcp doctor --json
```

`verify:source-runtime` analyzes a disposable JavaScript application through the
real CLI and a real stdio MCP subprocess and compares recovered graphs. It fails
on missing runtime, failed tool calls, or disagreement. It does not execute the
fixture or establish native-provider readiness, and does not change agent config.

For native decompilation, separately supply Ghidra and a full JDK, follow the
[Windows Ghidra requirements](windows-ghidra-p0.md), and run:

```sh
node scripts/rea.mjs doctor --provider ghidra --json
npm run verify:ghidra:windows
```

Record CLI/MCP validation separately from the selected provider's real results.
A missing engine is a blocked native workflow, not a successful setup. Never
report source tests or artifact inventory as evidence of successful decompilation.
