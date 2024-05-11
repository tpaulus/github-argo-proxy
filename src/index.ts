import { Buffer } from 'node:buffer';
import * as node_crypto from "node:crypto";

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (request.method !== "POST") return MethodNotAllowed(request);

		const signatureHeader: string | null = request.headers.get("x-hub-signature-256");

		if (!signatureHeader) {
			return new Response("Missing Request Signature", 
				{
					status: 401
				}
			);
		}
		
		if (!await verifySignature(
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

		const upstreamRequest = new Request(
			env.ARGO_URL,
			new Request(request, {
				headers: {
					...request.headers,
					"CF-Access-Client-Id": env.ACCESS_CLIENT_ID,
					"CF-Access-Client-Secret": env.ACCESS_CLIENT_SECRET,
				}
			})
		)

		// @ts-ignore
		return fetch(upstreamRequest);
	}
} satisfies ExportedHandler<Env>;

function MethodNotAllowed(request: Request): Response {
	return new Response(`Method ${request.method} not allowed.`, {
		status: 405,
		headers: {
		Allow: "GET",
		},
	});
}

async function verifySignature(secret: string, payload: string, header: string) {
	const signature = node_crypto
		.createHmac("sha256", secret)
		.update(payload)
		.digest("hex");
	let trusted = Buffer.from(`sha256=${signature}`, 'ascii');

	let untrusted = Buffer.from(header, 'ascii');
	return crypto.subtle.timingSafeEqual(trusted, untrusted);
};
