#!/usr/bin/env node
// Public MCP verification of seeded function bodies, using source-owned bytes.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

assert.equal(process.platform, "win32");
const fixture = fileURLToPath(
  new URL("../../../build/fixtures/rea-ghidra-windows.dll", import.meta.url),
);
// Add a valid PE64 Guard CF function table to source-owned fixture bytes. The
// PE loader creates entry-only functions from this table before auto-analysis.
const bytes = Buffer.alloc(1536);
(await readFile(fixture)).copy(bytes);
bytes.writeUInt32LE(0x400, 0x190); // section VirtualSize
bytes.writeUInt32LE(0x400, 0x198); // section SizeOfRawData
bytes.writeUInt32LE(0x1180, 0x158); // load-config directory RVA
bytes.writeUInt32LE(0x94, 0x15c); // directory size
bytes.writeUInt32LE(0x94, 0x380); // IMAGE_LOAD_CONFIG_DIRECTORY64.Size
bytes.writeBigUInt64LE(0x140001280n, 0x400); // GuardCFFunctionTable
bytes.writeBigUInt64LE(2n, 0x408); // GuardCFFunctionCount
bytes.writeUInt32LE(0x500, 0x410); // instrumented + function table present
bytes.writeUInt32LE(0x1000, 0x480);
bytes.writeUInt32LE(0x1010, 0x484);
const workspace = await mkdtemp(join(tmpdir(), "rea-seeded-windows-"));
const target = join(workspace, "seeded-cfg.dll");
const hash = async () =>
  createHash("sha256")
    .update(await readFile(target))
    .digest("hex");
const seeds = join(workspace, "seeds.tsv");
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL("../../rea.mjs", import.meta.url)), "mcp"],
  env: {
    ...process.env,
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_GHIDRA_SEED_FILE: seeds,
    REA_GHIDRA_DISABLED_ANALYZERS:
      "Disassemble Entry Points,Subroutine References,Function Start Search,Decompiler Switch Analysis,Reference,Data Reference,Scalar Operand References,Create Address Tables",
    REA_LOG_LEVEL: "silent",
  },
  stderr: "pipe",
});
const client = new Client({ name: "seeded-windows-regression", version: "1" });
try {
  await writeFile(target, bytes);
  const before = await hash();
  await writeFile(
    seeds,
    "0x140001000\tfunction\tseed_caller\n0x140001010\tfunction\tseed_callee\n",
  );
  transport.stderr?.resume();
  await client.connect(transport);
  transport.stderr?.resume();
  const call = async (name, arguments_) => {
    const response = await client.callTool(
      { name, arguments: arguments_ },
      { timeout: 600000 },
    );
    assert.notEqual(response.isError, true, JSON.stringify(response));
    return response.structuredContent;
  };
  await call("open_binary", { path: target, provider_id: "ghidra" });
  for (const [address, bytes, instructions] of [
    ["0x140001000", 9, 3],
    ["0x140001010", 6, 2],
  ]) {
    const evidence = await call("analyze_function", { procedure: address });
    assert.equal(
      evidence.analysis_profile.parameters.seeded_function_body_policy,
      "decode-refit-entry-only-v1",
    );
    assert.ok(
      evidence.limitations.some((text) => text.includes("2 already present")),
      "fixture must exercise preexisting PE loader functions, not only new seeds",
    );
    const value = evidence.raw_result.value;
    assert.equal(value.procedure.body.total_bytes, bytes, address);
    assert.equal(value.assembly.length, instructions, address);
    assert.ok(value.pseudocode.length > 0);
    if (address === "0x140001000") {
      assert.ok(
        value.callees.length > 0,
        "caller body must expose its call edge",
      );
    }
  }
  assert.equal(await hash(), before, "fixture bytes changed");
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
    await rm(workspace, { recursive: true, force: true });
  }
}
console.log(
  JSON.stringify({
    ok: true,
    real_mcp: true,
    seeded_bodies: true,
    assembly_and_calls: true,
    source_unchanged: true,
  }),
);
