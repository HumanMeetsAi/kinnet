/**
 * Verify a Kinnet participant from bytes, trusting nothing.
 *
 *   pnpm exec tsx examples/verify.mts <participant-id> [options]
 *
 *     --discovery <url>   discovery service to read from (default: the public one)
 *     --grants <path>     a grant chain file, or an https URL serving one, to verify too
 *     --tamper            flip one byte of the fetched profile before checking it, so you
 *                         can watch the signature check fail
 *
 * Discovery is a convenience here, never an authority: it is asked for bytes and every answer is
 * re-decided locally. The key log is replayed from its inception event and must derive the id
 * that was asked for; every record's signature is checked against the key state its ISSUER's own
 * log resolves to. A lying host fails a line; it cannot pass one.
 *
 * The checks live in `explainParticipant`, so this script is argv, a grant-chain file, and
 * printing — `npx @kinnet/verify <participant-id>` runs the same program from the package.
 */
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";

import { grantSchema, parseJsonStrict } from "@kinnet/protocol";
import { DEFAULT_EXPLAIN_DISCOVERY_URL, explainParticipant } from "@kinnet/verify";

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
  console.error("usage: pnpm exec tsx examples/verify.mts <participant-id> [--discovery <url>]");
  console.error("       [--grants <path-or-https-url>] [--tamper]");
  process.exit(2);
}
const discovery = (values.discovery ?? DEFAULT_EXPLAIN_DISCOVERY_URL).replace(/\/+$/, "");

console.log(`${participantId}\n  resolved from ${discovery}\n`);
const grants =
  values.grants === undefined
    ? undefined
    : grantSchema
        .array()
        .min(1)
        .parse(
          parseJsonStrict(
            values.grants.startsWith("https://")
              ? await (await fetch(values.grants)).text()
              : await readFile(values.grants, "utf8")
          )
        );
const result = await explainParticipant(participantId, {
  discoveryUrl: discovery,
  tamper: values.tamper,
  ...(grants ? { grants } : {})
});
for (const line of result.lines) {
  console.log(`${line.ok === null ? "·" : line.ok ? "✔" : "✘"} ${line.text}`);
}
const failures = result.lines.filter((line) => line.ok === false).length;
// The exit happens in the write callback: a discovery fetch leaves a keep-alive socket holding
// the event loop open, and on a piped stdout a bare exit here would truncate the lines above.
process.stdout.write(`\n${result.ok ? "all checks passed" : `${failures} check(s) failed`}\n`, () =>
  process.exit(result.ok ? 0 : 1)
);
