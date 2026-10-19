#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { artifactCliEvidence } from "./lib/artifact-e2e.mjs";

// Exercise public entrypoints, not test providers or imported application code.
const fixture = await mkdtemp(join(tmpdir(), "rea-source-runtime-"));
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL("./rea.mjs", import.meta.url)), "mcp"],
  env: {
    ...process.env,
    REA_ANALYSIS_PROVIDER: "auto",
    REA_LOG_LEVEL: "silent",
  },
  stderr: "pipe",
});
const client = new Client({ name: "source-runtime-verifier", version: "1" });
try {
  await writeFile(
    join(fixture, "package.json"),
    JSON.stringify({
      name: "rea-source-runtime-fixture",
      version: "1.0.0",
      main: "index.js",
    }),
  );
  await writeFile(
    join(fixture, "index.js"),
    "module.exports = { answer: 42 };\n",
  );
  const cli = await artifactCliEvidence(
    "analyze-javascript-application",
    fixture,
  );
  assert.equal(cli.operation, "analyze_javascript_application");
  transport.stderr?.resume();
  await client.connect(transport);
  transport.stderr?.resume();
  const reply = await client.callTool(
    {
      name: "analyze_javascript_application",
      arguments: { input_path: fixture },
    },
    { timeout: 60000 },
  );
  assert.notEqual(reply.isError, true, JSON.stringify(reply));
  const mcp = reply.structuredContent;
  assert.equal(mcp?.operation, cli.operation);
  assert.ok(cli.normalized_result.graph, "CLI omitted the recovered graph");
  assert.equal(cli.normalized_result.statistics.parsed_javascript_files, 1);
  assert.equal(cli.normalized_result.statistics.parse_failures, 0);
  assert.equal(
    mcp.normalized_result.root_artifact_sha256,
    cli.normalized_result.root_artifact_sha256,
  );
  assert.deepEqual(mcp.normalized_result.graph, cli.normalized_result.graph);
  console.log(
    JSON.stringify({
      ok: true,
      cli: true,
      mcp: true,
      javascript_graph_parity: true,
      native_decompilation:
        "not-tested; run doctor and the selected real-provider verification",
    }),
  );
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
    await rm(fixture, { recursive: true, force: true });
  }
}
