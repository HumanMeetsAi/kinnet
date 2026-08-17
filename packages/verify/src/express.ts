/**
 * Opt-in Express type augmentation.
 *
 * The middleware assigns the verification result to `req.verifiedAgent`. Teaching
 * `@types/express`'s `Request` about that property requires a `declare global`, and a
 * global augmentation in the package's main entry would land in the global type space of
 * every consumer that imports `@kinnet/verify` — including ones that never touch Express.
 * So it lives here instead, behind its own subpath, and a consumer opts in:
 *
 * ```ts
 * import "@kinnet/verify/express";
 * ```
 *
 * One such import anywhere in the program (commonly the entry module or a `*.d.ts`) covers
 * the whole compilation. Nothing in `@kinnet/verify`'s runtime or public API depends on it:
 * `middleware()` types its request structurally, so the middleware works with or without
 * this import — only the `req.verifiedAgent` property access needs it.
 */
import type { VerifiedAgent } from "./verifier.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- Express only exposes this via declaration merging
  namespace Express {
    interface Request {
      verifiedAgent?: VerifiedAgent;
    }
  }
}

export {};
