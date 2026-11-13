import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(root, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        // The test Worker exports a Scanner built around the tests' config.
        main: "./test/worker.js",
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            ADMIN_TOKEN: "test-admin-token-0123456789",
            WEBHOOK_SECRET: "test-webhook-secret-0123456789",
            ALERT_WEBHOOKS: JSON.stringify({ discord: "https://discord.com/api/webhooks/1/abc", json: "https://alerts.example.org/hook" }),
            MAIL_FROM: "Privacy <privacy@example.com>",
            PUBLIC_URL: "https://privacy.example.net",
            // Tests drive Scanner runs directly with chosen times.
            PAUSE_ALARMS: "1",
          },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.js"],
      include: ["test/**/*.test.js"],
    },
  };
});
