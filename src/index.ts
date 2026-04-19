import { Buffer } from 'node:buffer';
import * as node_crypto from "node:crypto";

type WebhookPayload = {
	repository?: {
		full_name?: string;
	};
};

type WebhookSecretMap = Record<string, string>;

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		return await Proxy.fetch(request, env, ctx)
	}
} satisfies ExportedHandler<Env>;

export class Proxy {
	static async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (request.method !== "POST") return this.MethodNotAllowed(request);

		const signatureHeader: string | null = request.headers.get("x-hub-signature-256");
		const payload = await request.clone().text();

		if (!signatureHeader) {
			return new Response("Missing Request Signature", 
				{
					status: 401
				}
			);
		}
		
		const webhookSecret = this.resolveWebhookSecret(env, payload);

		if (!webhookSecret || !await this.verifySignature(
			webhookSecret,
			payload,
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

	static resolveWebhookSecret(env: Env, payload: string): string | null {
		const webhookSecrets = this.parseWebhookSecrets(env.WEBHOOK_SECRETS);

		if (webhookSecrets) {
			const repositoryFullName = this.extractRepositoryFullName(payload);

			if (repositoryFullName && webhookSecrets[repositoryFullName]) {
				return webhookSecrets[repositoryFullName];
			}
		}

		return env.WEBHOOK_SECRET ?? null;
	}

	static MethodNotAllowed(request: Request): Response {
		return new Response(`Method ${request.method} not allowed.`, {
			status: 405,
			headers: {
			Allow: "GET",
			},
		});
	}

	static extractRepositoryFullName(payload: string): string | null {
		try {
			const parsed = JSON.parse(payload) as WebhookPayload;
			const repositoryFullName = parsed.repository?.full_name;

			if (typeof repositoryFullName === "string" && repositoryFullName.length > 0) {
				return repositoryFullName;
			}
		} catch (error) {
			console.log("Failed to parse webhook payload", error);
		}

		return null;
	}

	static parseWebhookSecrets(rawWebhookSecrets?: string): WebhookSecretMap | null {
		if (!rawWebhookSecrets) {
			return null;
		}

		try {
			const parsed = JSON.parse(rawWebhookSecrets);

			if (this.isWebhookSecretMap(parsed)) {
				return parsed;
			}

			console.log("WEBHOOK_SECRETS must be a JSON object keyed by owner/repo.");
		} catch (error) {
			console.log("Failed to parse WEBHOOK_SECRETS", error);
		}

		return null;
	}

	static isWebhookSecretMap(value: unknown): value is WebhookSecretMap {
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			return false;
		}

		return Object.values(value).every((secret) => typeof secret === "string");
	}

	static async verifySignature(secret: string, payload: string, header: string) {
		try {
			const signature = node_crypto
				.createHmac("sha256", secret)
				.update(payload)
				.digest("hex");
			let trusted = Buffer.from(`sha256=${signature}`, 'ascii');
			let untrusted = Buffer.from(header, 'ascii');

			if (trusted.byteLength !== untrusted.byteLength) {
				return false;
			}
			
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
