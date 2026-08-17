/**
 * The monotonic clock seam.
 *
 * Two clocks answer two different questions, and conflating them is a recurring source of
 * clock-related defects:
 *
 * - **Wall time** answers "what time does the world think it is". It is the ONLY legitimate
 *   input when comparing against a value another party stamped — an RFC 9421 `created`
 *   parameter, an OIDC `expires_in` we advertised. It can be stepped forwards or backwards
 *   at any moment by NTP, a VM snapshot restore, or an operator.
 * - **Monotonic time** answers "how long since we saw something". It never goes backwards and
 *   is unaffected by NTP corrections, so it is the only sound basis for a duration: nonce
 *   retention, cache TTLs, credential lifetimes, sweep cadence.
 *
 * `performance.now()` is the source rather than `process.hrtime.bigint()` because these are
 * published libraries that claim to run on Cloudflare Workers, Deno and Bun as well as Node
 * (see `@kinnet/verify`'s README). `performance.now()` is specified as monotonic and exists on
 * all of them; `process.hrtime` is Node-only. Milliseconds as a double is ample: the shortest
 * duration measured here is a 60-second cache TTL.
 *
 * ## The origin resets on restart, and that is fine — but only because of what these are used
 *
 * `performance.now()` counts from an arbitrary origin, so the timeline is meaningless across
 * processes and resets on restart. Every consumer of this seam is an in-memory `Map` that is
 * destroyed by the same restart, so entries and the timeline they were stamped on die together
 * — there is never a surviving deadline to compare against a reset clock. A durable backend
 * MUST NOT persist a monotonic deadline; it has to store wall-clock expiry and re-derive. This
 * is called out at each call site that could grow one.
 *
 * ## Runtime caveat: "process-local, advancing with elapsed time" is not universal
 *
 * On Cloudflare Workers `performance.now()` does NOT advance freely: the value is frozen
 * between I/O operations, and `timeOrigin` is reported as 0. So on that runtime the clock
 * advances in steps tied to I/O rather than continuously, and it is not a process-local
 * elapsed-CPU-time counter in the way the name suggests.
 *
 * That is safe for every use here, and the direction matters: a clock that advances more
 * slowly than real time makes retention deadlines arrive LATER, so nonces are held LONGER and
 * caches expire LATER. Over-retention costs memory against a bounded ceiling; it never
 * reclaims a nonce early, which is the direction that would re-open replay. The visible effect
 * on such a runtime is that a ceiling is reached sooner under load, not that a replay control
 * weakens.
 */

/**
 * Milliseconds since an arbitrary origin. Never decreases, but does not necessarily advance
 * with real time — see the runtime caveat above; a runtime may advance it in steps.
 */
export type MonotonicClock = () => number;

/**
 * The default monotonic source. Injectable everywhere it is consumed so tests can drive
 * durations deterministically instead of sleeping.
 */
export const defaultMonotonicClock: MonotonicClock = () => performance.now();
