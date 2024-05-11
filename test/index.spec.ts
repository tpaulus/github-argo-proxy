// test/index.spec.ts
import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { vi, describe, test, expect, beforeEach, afterEach } from 'vitest';
import worker from '../src/index';
import { Proxy } from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('Basic Request Validation', () => {
	test.each([
		["GET", false],
		["HEAD", false],
		["POST", true],
		["PUT", false],
		["DELETE", false],
		["OPTIONS", false],
		["TRACE", false],
		["PATCH", false],
	])('Require POST - Verb: %s', async (verb: string, allowed: boolean) => {
		const request = new IncomingRequest('http://example.com', {
			method: verb
		});
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);

		if (allowed) {
			expect(response.status).toEqual(401)
		} else {
			expect(response.status).toEqual(405)
		}
	});

	test.each([
		[true],
		[false]
	])("Require Signature Header - Header Present: %s", async (include_header: boolean) => {
		const request = new IncomingRequest('http://example.com', {
			method: "POST",
			headers: include_header ? {"x-hub-signature-256": "some-value"}: undefined
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);

		if (include_header) {
			expect(response.status).toEqual(403)
		} else {
			expect(response.status).toEqual(401)
		}
	})
});

describe('Auth', () => {
	beforeEach(async () => {
		vi.spyOn(Proxy, 'forwardToUpstream').mockReturnValue(Promise.resolve(new Response(null, {
			status: 204
		})))
	})

	afterEach(async () => {
		vi.restoreAllMocks()
	})

	test("Verify Signature", async () => {
		const request = new IncomingRequest('http://example.com', {
			method: "POST",
			headers: {
				"x-hub-signature-256": "sha256=848638c8ec86e4110e18032190b3e93ec0213b3f1b65797807b84482dfe7cd87",
			},
			body: "This is a sample body"
		});

		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);

		expect(response.status).toEqual(204)
	})
});

describe('Credential Injection', () => {
	beforeEach(async () => {
		vi.spyOn(Proxy, 'forwardToUpstream').mockImplementation((request: Request) => {
			if (request.headers?.get("CF-Access-Client-Id") === "access-client" &&
					request.headers?.get("CF-Access-Client-Secret") === "access-secret") {
				return Promise.resolve(new Response(null, {
					status: 200
				}))
			} else {
				return Promise.resolve(new Response(null, {
					status: 403
				}))
			}
		})
	})

	afterEach(async () => {
		vi.restoreAllMocks()
	})

	test("Verify Credentials Injected", async () => {
		const request = new IncomingRequest('http://example.com', {
			method: "POST",
			headers: {
				"x-hub-signature-256": "sha256=848638c8ec86e4110e18032190b3e93ec0213b3f1b65797807b84482dfe7cd87",
			},
			body: "This is a sample body"
		});

		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);

		expect(response.status).toEqual(200)
	})
});