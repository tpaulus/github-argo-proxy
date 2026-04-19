import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        bindings: {
          "ARGO_URL": "https://example.com",
          "ACCESS_CLIENT_ID": "access-client",
          "ACCESS_CLIENT_SECRET": "access-secret",
          "WEBHOOK_SECRET": "webhook-secret"
        }
      },
      wrangler: { configPath: "./wrangler.toml" },
    }),
  ],
});
