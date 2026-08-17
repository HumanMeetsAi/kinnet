/**
 * Verify a Kinnet participant from bytes, trusting nothing.
 *
 *   npx @kinnet/verify <participant-id> [options]
 *
 *     --discovery <url>   discovery service to read from (default: the public one)
 *     --grants <path>     a grant chain file, or an https URL serving one, to verify too
 *     --tamper            flip one byte of the fetched profile before checking it, so you
 *                         can watch the signature check fail
 *
 * Every check lives in `explainParticipant`; this file is argv, a grant-chain file, and
 * printing. Exit code is 0 only if no line came back ✘.
 */
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";

import { grantSchema, parseJsonStrict, type Grant } from "@kinnet/protocol";

import { DEFAULT_EXPLAIN_DISCOVERY_URL, explainParticipant } from "./explain.js";

/** The chain the holder gave you: a local file, or an https URL serving one. */
async function readGrants(source: string): Promise<Grant[]> {
  const text = source.startsWith("https://")
    ? await (await fetch(source)).text()
    : await readFile(source, "utf8");
  return grantSchema.array().min(1).parse(parseJsonStrict(text));
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    options: {
      discovery: { type: "string" },
      grants: { type: "string" },
      tamper: { type: "boolean", default: false }
    },
    allowPositionals: true
  });
  const participantId = positionals[0];
  if (participantId === undefined) {
    console.error("usage: kinnet-verify <participant-id> [--discovery <url>]");
    console.error("       [--grants <path-or-https-url>] [--tamper]");
    process.exit(2);
  }
  const discovery = (values.discovery ?? DEFAULT_EXPLAIN_DISCOVERY_URL).replace(/\/+$/, "");

  console.log(`${participantId}\n  resolved from ${discovery}\n`);
  const grants = values.grants === undefined ? undefined : await readGrants(values.grants);
  const result = await explainParticipant(participantId, {
    discoveryUrl: discovery,
    tamper: values.tamper,
    ...(grants ? { grants } : {})
  });
  for (const line of result.lines) {
    console.log(`${line.ok === null ? "·" : line.ok ? "✔" : "✘"} ${line.text}`);
  }
  const failures = result.lines.filter((line) => line.ok === false).length;
  // The exit happens in the write callback, not after it: a discovery fetch leaves a keep-alive
  // socket holding the event loop, so this process has to end itself — and on a piped stdout
  // (asynchronous on macOS) a bare `process.exit` here would truncate the lines above.
  process.stdout.write(
    `\n${result.ok ? "all checks passed" : `${failures} check(s) failed`}\n`,
    () => process.exit(result.ok ? 0 : 1)
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
