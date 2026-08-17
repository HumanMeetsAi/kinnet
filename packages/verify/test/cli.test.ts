/**
 * The `kinnet-verify` bin, run as a real process against a real socket.
 *
 * `explain.test.ts` covers the checks; this covers the thing only a spawned process can show —
 * that the committed `bin/kinnet-verify.js` shim (onto the built `dist/cli.js`) prints its lines and ends with an exit
 * code a shell can branch on. The package's build runs before its tests, so the artifact under
 * test is the emitted file rather than a source module re-compiled here.
 */
import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import { createIdentity, signRecord } from "@kinnet/crypto";
import type { ParticipantProfile } from "@kinnet/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = fileURLToPath(new URL("../bin/kinnet-verify.js", import.meta.url));

const seed = (fill: number) => new Uint8Array(32).fill(fill);
const agent = createIdentity({ currentSeed: seed(11), nextSeed: seed(12) });

const profile = signRecord(
  {
    id: agent.id,
    type: "agent",
    displayName: "HMAI Sales Agent",
    capabilities: [] as string[],
    verifiedDomains: [] as string[],
    updatedAt: "2026-06-01T00:00:00.000Z"
  },
  agent.currentKeys[0]!.secretKey
) as ParticipantProfile;

/** The routes this run reads, as static JSON. Everything else answers 404 with an empty body. */
const routes: Record<string, unknown> = {
  [`/participants/${agent.id}/key-log`]: { events: agent.log },
  [`/participants/${agent.id}`]: profile,
  [`/participants/${agent.id}/relationships`]: { relationships: [] },
  [`/participants/${agent.id}/claims`]: { claims: [] }
};

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const body = routes[path];
    if (body === undefined) {
      response.writeHead(404).end("");
      return;
    }
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
  });
  // Port 0: the OS picks a free one, so nothing here can collide with another test run or with
  // a service the developer happens to have up.
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

/** One run of the bin. Resolves on any exit, because the exit code is part of what is asserted. */
function runCli(...args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], (error, stdout, stderr) => {
      const code = error === null ? 0 : ((error as { code?: number }).code ?? 1);
      resolve({ code, stdout, stderr });
    });
  });
}

describe("the kinnet-verify bin", () => {
  it("prints the checks and exits 0 for a participant that verifies", async () => {
    const { code, stdout } = await runCli(agent.id, "--discovery", origin);

    expect(code).toBe(0);
    expect(stdout).toContain(`${agent.id}\n  resolved from ${origin}\n`);
    expect(stdout).toContain("✔ ");
    expect(stdout).toContain("HMAI Sales Agent");
    expect(stdout.trimEnd().endsWith("all checks passed")).toBe(true);
  });

  it("exits 1 when a check fails", async () => {
    // `--tamper` flips one byte of the fetched display name, so the profile's own signature stops
    // verifying against the key log: a failed line, and a status a shell can branch on.
    const { code, stdout } = await runCli(agent.id, "--discovery", origin, "--tamper");

    expect(code).toBe(1);
    expect(stdout).toContain("✘ profile signed by the current key");
    expect(stdout.trimEnd().endsWith("1 check(s) failed")).toBe(true);
  });

  it("exits 1 for a participant discovery has never heard of", async () => {
    const { code, stdout } = await runCli("pk_zNobodyAtAll", "--discovery", origin);

    expect(code).toBe(1);
    expect(stdout).toContain("discovery serves none");
  });

  it("refuses a run with no participant id", async () => {
    const { code, stderr } = await runCli();

    expect(code).toBe(2);
    expect(stderr).toContain("usage: kinnet-verify");
  });
});
