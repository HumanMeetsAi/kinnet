/**
 * The discovery view's outbound fetch POLICY: a deadline on the whole exchange, a cap on the
 * bytes a response may deliver, and a flat refusal to follow redirects.
 *
 * WHAT THESE CATCH, mutation by mutation. Delete the `signal` and a host that writes headers
 * and then freezes holds its throttle slot forever — sixteen of them retire the view. Move the
 * byte check from the streaming loop to `await response.text()` and the cap still "passes"
 * while the memory it exists to protect has already been spent. Drop `redirect: "manual"` and
 * the verifier fetches whatever address the untrusted host names, which is blind SSRF from
 * inside the process. Collapse the three reasons into one and a caller cannot tell a stalled
 * host from an oversized one, nor a 503 that is worth retrying from a 401 that is not.
 *
 * REAL SOCKETS, not a fake `fetch`. Every one of these lives in the parts a stub cannot
 * reproduce: whether the abort actually tears down a body mid-stream, whether the cap fires
 * before the bytes are buffered, whether the redirect target is contacted. A hand-rolled
 * `fetch` would only prove that the code under test calls the functions it calls.
 *
 * The happy path is here too, but only as the non-vacuity control: a refusal test suite that
 * would also pass if every lookup failed proves nothing.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { createIdentity } from "@kinnet/crypto";
import { afterEach, describe, expect, it } from "vitest";

import {
  createDiscoveryView,
  DEFAULT_FETCH_DEADLINE_MS,
  DEFAULT_MAX_RESPONSE_BYTES,
  type DiscoveryViewOptions
} from "../src/discovery-view.js";
import {
  isVerifyAuthReason,
  isVerifyCapacityReason,
  KNOWN_VERIFY_REASONS,
  VerifyCapacityError,
  VerifyError
} from "../src/errors.js";

const identity = createIdentity({
  currentSeed: new Uint8Array(32).fill(7),
  nextSeed: new Uint8Array(32).fill(8)
});

/** A real HTTP server on an ephemeral port, torn down after every test. */
type Stub = {
  readonly url: string;
  /** Requests this server was actually asked for — 0 is the assertion the redirect test needs. */
  readonly hits: () => number;
  readonly paths: () => readonly string[];
};

const running: Server[] = [];

async function startStub(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  const paths: string[] = [];
  const server = createServer((req, res) => {
    paths.push(req.url ?? "");
    // A client that refuses mid-body destroys the socket under the server's feet; without this
    // the resulting ECONNRESET becomes an unhandled 'error' event and kills the test run.
    res.on("error", () => undefined);
    handler(req, res);
  });
  server.on("clientError", () => undefined);
  running.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const stub: Stub = {
    url: `http://127.0.0.1:${port}`,
    hits: () => paths.length,
    paths: () => paths
  };
  return stub;
}

afterEach(async () => {
  await Promise.all(
    running.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          // Stalled and refused responses leave sockets open by design; without this the close
          // never completes and vitest reports an open handle.
          server.closeAllConnections();
          server.close(() => resolve());
        })
    )
  );
});

const view = (discoveryUrl: string, options: Omit<DiscoveryViewOptions, "discoveryUrl"> = {}) =>
  createDiscoveryView({ discoveryUrl, ...options });

/** The one honest answer: this identity's key log, small and well formed. */
function serveKeyLog(res: ServerResponse): void {
  const body = JSON.stringify({ events: identity.log });
  res.writeHead(200, {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body))
  });
  res.end(body);
}

/**
 * Streams `totalBytes` at the client as fast as it will take them, stopping the moment the
 * client walks away. `written` is the point of it: the cap's whole claim is that the transfer
 * is cut short, and the only place that is observable is how much the SERVER got to send.
 */
function flood(res: ServerResponse, totalBytes: number, written: { count: number }): void {
  const chunk = Buffer.alloc(64 * 1024, 0x20);
  let stopped = false;
  const stop = (): void => {
    stopped = true;
  };
  res.on("close", stop);
  res.on("error", stop);
  res.writeHead(200, { "content-type": "application/json" });
  const pump = (): void => {
    while (!stopped && written.count < totalBytes) {
      written.count += chunk.byteLength;
      if (!res.write(chunk)) {
        res.once("drain", pump);
        return;
      }
    }
    if (!stopped) {
      res.end();
    }
  };
  pump();
}

async function refusalOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    (value) => value,
    (error: unknown) => error
  );
}

describe("discovery fetch deadline", () => {
  it("pins the defaults, so a caller relying on them can see them move", () => {
    expect(DEFAULT_FETCH_DEADLINE_MS).toBe(5_000);
    // 1 MiB: ~5x the ~192 KiB a schema-maximal key log can reach. See the constant's docblock
    // for the arithmetic; this pins the conclusion so the two cannot drift apart silently.
    expect(DEFAULT_MAX_RESPONSE_BYTES).toBe(1_048_576);
  });

  it("refuses a response whose body never finishes, and gives the slot back", async () => {
    const stub = await startStub((req, res) => {
      if (req.url?.includes("stalled")) {
        // Headers arrive promptly and the body never does — the shape a headers-only deadline
        // would sail straight past, and the one that occupies a slot indefinitely.
        res.writeHead(200, { "content-type": "application/json" });
        res.write("{");
        return;
      }
      serveKeyLog(res);
    });
    // One slot and one queue place: if the stalled fetch leaked its slot, the healthy lookup
    // below would queue behind a slot nobody holds and die on the queue deadline instead.
    const discovery = view(stub.url, {
      maxConcurrentFetches: 1,
      maxQueuedFetches: 1,
      fetchQueueTimeoutMs: 2_000,
      fetchDeadlineMs: 150
    });

    const refusal = await refusalOf(discovery.getKeyState("pk_zstalled"));
    expect(refusal).toBeInstanceOf(VerifyCapacityError);
    expect((refusal as VerifyCapacityError).reason).toBe("discovery_fetch_deadline");
    // 503, not 401: the host may be fine in a second, and the caller should retry rather than
    // go looking at its credentials.
    expect((refusal as VerifyCapacityError).status).toBe(503);

    // THE SLOT CAME BACK. This is the failure mode the module warns about — "a slot that leaks
    // on the error path is permanent" — and a new error path is exactly where it would happen.
    expect(await discovery.getKeyState(identity.id)).not.toBeNull();
    expect(stub.hits()).toBe(2);
  });

  it("does not trip the deadline on a response that arrives in time", async () => {
    // The control. Without it "the stalled one failed" could just mean nothing ever succeeds.
    const stub = await startStub((_req, res) => serveKeyLog(res));
    const discovery = view(stub.url, { fetchDeadlineMs: 2_000 });
    expect(await discovery.getKeyState(identity.id)).not.toBeNull();
  });
});

describe("discovery response byte cap", () => {
  it("cuts an endless body off mid-stream instead of buffering it first", async () => {
    const written = { count: 0 };
    // Eight megabytes on offer against a 4 KiB cap. A cap applied after `response.text()`
    // would let all eight through the process before saying no.
    const offered = 8 * 1024 * 1024;
    const stub = await startStub((_req, res) => flood(res, offered, written));
    const discovery = view(stub.url, { maxResponseBytes: 4_096, fetchDeadlineMs: 5_000 });

    const refusal = await refusalOf(discovery.getKeyState("pk_zflood"));
    expect(refusal).toBeInstanceOf(VerifyError);
    expect((refusal as VerifyError).reason).toBe("discovery_response_too_large");
    // NOT capacity: the host chose to send this and will send it again, so 503 ("retry, it
    // may clear") would be a lie told to every client and to alerting.
    expect(refusal).not.toBeInstanceOf(VerifyCapacityError);
    expect((refusal as VerifyError).status).toBe(401);

    // THE MID-STREAM PROOF, taken from the number THIS CODE counted rather than from the wire.
    // `readCappedBody` refuses on the first chunk that carries the running total past the cap,
    // so what it accumulated is `cap + one chunk` — and a chunk is however much came off the
    // socket in one read. Buffer-then-check would report the full eight megabytes here, so the
    // gap between this number and `offered` is the whole assertion. Measured at ~64 KiB (one
    // undici read) against the 4 KiB cap; the bound below leaves 16x for a runtime that reads
    // larger, and still rules out anything resembling the 8 MiB on offer.
    const streamed = Number(
      / is (\d+) bytes \(streamed\)/.exec((refusal as VerifyError).message)![1]
    );
    expect(streamed).toBeGreaterThan(4_096);
    expect(streamed).toBeLessThan(1024 * 1024);

    // The wire-side observation, kept only as a sanity bound and DELIBERATELY LOOSE. How much
    // the server got out before the cancel landed is a property of kernel socket buffers and
    // abort-propagation latency — the OS's business, not this module's — and it moves with the
    // machine: ~576 KiB on a developer laptop, ~2.6 MiB on a 2-vCPU CI runner. Anything tighter
    // than "not the whole offer" is a test of the scheduler. The real bound is `streamed` above.
    expect(written.count).toBeLessThan(offered / 2);
  });

  it("catches an oversized body that declared no length at all", async () => {
    // THE HEADER EXIT IS NOT THE GUARD. A hostile host simply omits `content-length` — HTTP
    // chunked framing does exactly that — and the cheap early exit has nothing to look at. The
    // streaming count is what has to be the authority, and this is the case that proves it is.
    //
    // (The mirror-image lie — a small `content-length` with a larger body behind it — is not
    // reachable over real HTTP: the declared length IS the framing, so a client reads exactly
    // that many bytes and the excess is never delivered as part of this response. Omission is
    // the lie a host can actually tell, so omission is what is tested.)
    const body = Buffer.alloc(64 * 1024, 0x20);
    const stub = await startStub((_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
      res.end(body);
    });
    const discovery = view(stub.url, { maxResponseBytes: 4_096 });

    const refusal = await refusalOf(discovery.getKeyState("pk_zchunked"));
    expect((refusal as VerifyError).reason).toBe("discovery_response_too_large");
    // Non-vacuous: the response really did arrive without a declared length, so nothing but
    // the streaming check could have refused it.
    expect((refusal as VerifyError).message).toContain("streamed");
  });

  it("refuses an over-cap content-length without reading the body", async () => {
    // The server declares a gigabyte and then sends NOTHING. If the view read the body before
    // deciding, it would sit here until its deadline; the header exit means it refuses at once.
    const stub = await startStub((_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "content-length": "1000000000" });
      // Node holds headers back until the first body write, and the whole point here is that
      // there is never a body write. Flushing is what puts the declaration on the wire alone.
      res.flushHeaders();
    });
    const discovery = view(stub.url, { maxResponseBytes: 4_096, fetchDeadlineMs: 3_000 });

    const startedAt = Date.now();
    const refusal = await refusalOf(discovery.getKeyState("pk_zdeclared"));
    const elapsed = Date.now() - startedAt;

    expect((refusal as VerifyError).reason).toBe("discovery_response_too_large");
    expect((refusal as VerifyError).message).toContain("declared");
    // The timing IS the assertion: a body-first implementation could only have got here by
    // waiting out the 3 s deadline, and would have reported the deadline reason besides.
    expect(elapsed).toBeLessThan(1_000);
  });

  it("does not let Infinity delete the cap", async () => {
    // `maxResponseBytes: Infinity` asks for a limiter with no limit — nothing is ever
    // `> Infinity`. `boundedThrottleOption` falls back to the decided default instead, so an
    // over-default body is still refused.
    const written = { count: 0 };
    const offered = 8 * 1024 * 1024;
    const stub = await startStub((_req, res) => flood(res, offered, written));
    const discovery = view(stub.url, {
      maxResponseBytes: Number.POSITIVE_INFINITY,
      fetchDeadlineMs: 5_000
    });

    const refusal = await refusalOf(discovery.getKeyState("pk_zinfinite"));
    expect((refusal as VerifyError).reason).toBe("discovery_response_too_large");
    // Refused at the 1 MiB default, not at the eight megabytes on offer.
    expect(written.count).toBeLessThan(offered / 2);
  });

  it("lets an in-limit response through and caches it", async () => {
    // The non-vacuity control for the whole cap: a well-formed key log is nowhere near the cap
    // and must be untouched by any of this, including the caching underneath it.
    const stub = await startStub((_req, res) => serveKeyLog(res));
    const discovery = view(stub.url, { maxResponseBytes: 64 * 1024 });

    expect(await discovery.getKeyState(identity.id)).not.toBeNull();
    expect(discovery.cacheSize()).toBe(1);
    // Second lookup is served from cache: the server is never asked again.
    expect(await discovery.getKeyState(identity.id)).not.toBeNull();
    expect(stub.hits()).toBe(1);
  });
});

describe("discovery redirects", () => {
  it("refuses a redirect and never contacts the target", async () => {
    // The SSRF shape: the untrusted host names an address the operator never configured, and a
    // following client fetches it from inside the verifier's network.
    const target = await startStub((_req, res) => serveKeyLog(res));
    const redirector = await startStub((_req, res) => {
      res.writeHead(302, { location: `${target.url}/participants/pk_zredirect/key-log` });
      res.end();
    });
    const discovery = view(redirector.url, { fetchDeadlineMs: 2_000 });

    const refusal = await refusalOf(discovery.getKeyState("pk_zredirect"));
    expect(refusal).toBeInstanceOf(VerifyError);
    expect((refusal as VerifyError).reason).toBe("discovery_redirect_refused");
    expect(refusal).not.toBeInstanceOf(VerifyCapacityError);
    expect((refusal as VerifyError).status).toBe(401);

    // THE ASSERTION THAT MATTERS. The redirector was asked; the target never was. A view that
    // followed would have got a perfectly good key log from a host nobody authorized, and the
    // lookup would have SUCCEEDED — which is why this cannot be inferred from the refusal.
    expect(redirector.hits()).toBe(1);
    expect(target.hits()).toBe(0);
  });

  it("gives the slot back after refusing a redirect", async () => {
    const stub = await startStub((req, res) => {
      if (req.url?.includes("redirected")) {
        res.writeHead(302, { location: "http://127.0.0.1:1/elsewhere" });
        res.end();
        return;
      }
      serveKeyLog(res);
    });
    const discovery = view(stub.url, {
      maxConcurrentFetches: 1,
      maxQueuedFetches: 1,
      fetchQueueTimeoutMs: 1_000
    });

    const refusal = await refusalOf(discovery.getKeyState("pk_zredirected"));
    expect((refusal as VerifyError).reason).toBe("discovery_redirect_refused");
    // A refusal thrown between the fetch and the body read is a fresh path through the
    // `finally`; the slot has to come back on it too.
    expect(await discovery.getKeyState(identity.id)).not.toBeNull();
  });
});

describe("discovery unreachable or failing", () => {
  /** A port that was bound and released, so a connection to it is refused at once. */
  async function refusedBaseUrl(): Promise<string> {
    const server = createServer(() => undefined);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return `http://127.0.0.1:${port}`;
  }

  it("maps a refused connection to a 503, not a 401", async () => {
    // Discovery being unreachable is transient: the caller should retry, not conclude its
    // credentials are wrong. Before this the raw `TypeError` a failed fetch throws reached the
    // surface unclassified and was answered 401.
    const discovery = view(await refusedBaseUrl(), { fetchDeadlineMs: 2_000 });
    const refusal = await refusalOf(discovery.getKeyState(identity.id));
    expect(refusal).toBeInstanceOf(VerifyCapacityError);
    expect((refusal as VerifyCapacityError).reason).toBe("discovery_unavailable");
    expect((refusal as VerifyCapacityError).status).toBe(503);
  });

  it("gives the slot back after a refused connection", async () => {
    // A brand-new error path through the `finally`; a slot leaked here wedges the view exactly
    // as a leaked slot on any other error path would.
    const discovery = view(await refusedBaseUrl(), {
      maxConcurrentFetches: 1,
      maxQueuedFetches: 1,
      fetchQueueTimeoutMs: 1_000,
      fetchDeadlineMs: 2_000
    });
    const first = await refusalOf(discovery.getKeyState(identity.id));
    expect((first as VerifyCapacityError).reason).toBe("discovery_unavailable");
    // The second lookup must get its own slot rather than queue behind one nobody holds; it
    // fails the same way (host still down), but on `discovery_unavailable`, not a queue timeout.
    const second = await refusalOf(discovery.getKeyState(identity.id));
    expect((second as VerifyCapacityError).reason).toBe("discovery_unavailable");
  });

  it("maps a 5xx to a 503 the caller should retry", async () => {
    const stub = await startStub((_req, res) => {
      res.writeHead(503, { "content-type": "text/plain" });
      res.end("upstream unavailable");
    });
    const discovery = view(stub.url, { fetchDeadlineMs: 2_000 });
    const refusal = await refusalOf(discovery.getKeyState(identity.id));
    expect(refusal).toBeInstanceOf(VerifyCapacityError);
    expect((refusal as VerifyCapacityError).reason).toBe("discovery_unavailable");
    expect((refusal as VerifyCapacityError).status).toBe(503);
  });

  it("maps a 429 to a 503 as well", async () => {
    const stub = await startStub((_req, res) => {
      res.writeHead(429, { "content-type": "text/plain" });
      res.end("slow down");
    });
    const discovery = view(stub.url, { fetchDeadlineMs: 2_000 });
    const refusal = await refusalOf(discovery.getKeyState(identity.id));
    expect((refusal as VerifyCapacityError).reason).toBe("discovery_unavailable");
    expect((refusal as VerifyCapacityError).status).toBe(503);
  });

  it("leaves a 4xx other than 404 as a 401 — the host rejected the request", async () => {
    // A 403 is the discovery host REJECTING the lookup, which a retry cannot change. It must NOT
    // become a capacity 503, and it must NOT become a `null` "no record" that the redirect/oversize
    // refusals are grouped with — it stays a plain error the surface answers 401.
    const stub = await startStub((_req, res) => {
      res.writeHead(403, { "content-type": "text/plain" });
      res.end("forbidden");
    });
    const discovery = view(stub.url, { fetchDeadlineMs: 2_000 });
    const refusal = await refusalOf(discovery.getKeyState(identity.id));
    expect(refusal).toBeInstanceOf(Error);
    expect(refusal).not.toBeInstanceOf(VerifyCapacityError);
    expect((refusal as Error).message).toContain("403");
  });

  it("preserves a typed VerifyError a custom fetch throws, rather than relabelling it", async () => {
    // A wrapping fetch may classify its own refusal (e.g. a self-imposed throttle throwing a
    // capacity error). That reason is more specific than "unreachable host" and must survive —
    // only an UNCLASSIFIED throw becomes discovery_unavailable.
    const discovery = view("http://discovery.invalid", {
      fetch: () => {
        throw new VerifyCapacityError(
          "discovery_fetch_capacity",
          "custom fetch refused on its own capacity"
        );
      }
    });
    const refusal = await refusalOf(discovery.getKeyState(identity.id));
    expect((refusal as VerifyCapacityError).reason).toBe("discovery_fetch_capacity");
  });

  it("a 404 is not an outage — it is the absence of a record", async () => {
    // The control that keeps the 5xx test honest: a missing key log resolves to `null` (deny),
    // never a capacity error, so "not found" and "host down" stay tellable apart.
    const stub = await startStub((_req, res) => {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    });
    const discovery = view(stub.url, { fetchDeadlineMs: 2_000 });
    expect(await discovery.getKeyState(identity.id)).toBeNull();
  });
});

describe("classification of the new refusals", () => {
  it("answers 503 for the deadline and 401 for the host's own misbehaviour", () => {
    // `isVerifyCapacityReason` is what consumers use to pick the status, so getting this wrong
    // mislabels every one of these responses.
    expect(isVerifyCapacityReason("discovery_fetch_deadline")).toBe(true);
    expect(isVerifyAuthReason("discovery_fetch_deadline")).toBe(false);

    // Retrying cannot change either of these: the host will send the same oversized body and
    // the same redirect. They sit with `agent_key_log_unresolved` — "discovery yielded no
    // usable record, so this request is denied" — rather than with the capacity refusals.
    expect(isVerifyCapacityReason("discovery_response_too_large")).toBe(false);
    expect(isVerifyAuthReason("discovery_response_too_large")).toBe(true);
    expect(isVerifyCapacityReason("discovery_redirect_refused")).toBe(false);
    expect(isVerifyAuthReason("discovery_redirect_refused")).toBe(true);

    // The pre-existing throttle reasons keep their meanings; the new deadline is a distinct
    // condition and did not replace either of them.
    expect(isVerifyCapacityReason("discovery_fetch_timeout")).toBe(true);
    expect(isVerifyCapacityReason("discovery_fetch_capacity")).toBe(true);

    // An unreachable or failing host is capacity too — the transport-layer sibling of the
    // deadline, and the reason this whole block exists.
    expect(isVerifyCapacityReason("discovery_unavailable")).toBe(true);
    expect(isVerifyAuthReason("discovery_unavailable")).toBe(false);
  });

  it("lists every new reason in the exported vocabulary", () => {
    // The compile-time `SameSet` proof covers the union against the list; this covers the list
    // against what a consumer enumerating it will actually see.
    expect(KNOWN_VERIFY_REASONS).toContain("discovery_fetch_deadline");
    expect(KNOWN_VERIFY_REASONS).toContain("discovery_unavailable");
    expect(KNOWN_VERIFY_REASONS).toContain("discovery_response_too_large");
    expect(KNOWN_VERIFY_REASONS).toContain("discovery_redirect_refused");
  });
});
