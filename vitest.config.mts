import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    pool: "@cloudflare/vitest-pool-workers",
    poolOptions: {
      workers: {
        miniflare: {
          bindings: {
            "ARGO_URL": "https://example.com",
            "ACCESS_CLIENT_ID": "access-client",
            "ACCESS_CLIENT_SECRET": "access-secret",
            "WEBHOOK_SECRET": "webhook-secret"
          }
        },
        wrangler: { configPath: "./wrangler.toml" },
      },
    },
  },
});
