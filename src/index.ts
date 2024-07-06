import { Buffer } from 'node:buffer';
import * as node_crypto from "node:crypto";

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		return await Proxy.fetch(request, env, ctx)
	}
} satisfies ExportedHandler<Env>;

export class Proxy {
	static async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (request.method !== "POST") return this.MethodNotAllowed(request);

		const signatureHeader: string | null = request.headers.get("x-hub-signature-256");

		if (!signatureHeader) {
			return new Response("Missing Request Signature", 
				{
					status: 401
				}
			);
		}
		
		if (!await this.verifySignature(
			env.WEBHOOK_SECRET,
			await request.clone().text(),
			signatureHeader
		)) {
			return new Response("Invalid Request Signature", 
				{
					status: 403
				}
			);
		}

		const headers = new Headers(request.headers);
        headers.set("CF-Access-Client-Id", env.ACCESS_CLIENT_ID);
        headers.set("CF-Access-Client-Secret", env.ACCESS_CLIENT_SECRET);


		const upstreamRequest = new Request(
			env.ARGO_URL,
			new Request(request, {
				method: request.method,
				headers: headers,
				body: request.body
			})
		)

		// @ts-ignore
		return this.forwardToUpstream(upstreamRequest);
	}

	static async forwardToUpstream(request: Request): Promise<Response> {
		// @ts-ignore
		return fetch(request);
	}

	static MethodNotAllowed(request: Request): Response {
		return new Response(`Method ${request.method} not allowed.`, {
			status: 405,
			headers: {
			Allow: "GET",
			},
		});
	}

	static async verifySignature(secret: string, payload: string, header: string) {
		try {
			const signature = node_crypto
				.createHmac("sha256", secret)
				.update(payload)
				.digest("hex");
			let trusted = Buffer.from(`sha256=${signature}`, 'ascii');

			let untrusted = Buffer.from(header, 'ascii');
			console.log(`Signature Verification Failed - Expected: '${trusted}', but got: '${untrusted}'`)

			if (crypto.subtle.timingSafeEqual(trusted, untrusted)) {
				return true;
			} else {
				console.log(`Signature Verification Failed - Expected: '${trusted}', but got: '${untrusted}'`)
				return false;
			}
		} catch (e) {
			console.log(e)
			return false;
		}
	}
}
