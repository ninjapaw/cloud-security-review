import { join } from 'node:path';
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: join('studio', 'test'),
  fullyParallel: false,
  workers: 1,
  timeout: 60000,
  forbidOnly: Boolean(process.env.CI),
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4331',
    channel: process.env.PLAYWRIGHT_CHANNEL,
    acceptDownloads: true,
    viewport: { width: 1440, height: 1000 },
  },
  webServer: {
    command: 'node scripts/start-studio.mjs --no-open --no-build --port 4331',
    url: 'http://127.0.0.1:4331',
    reuseExistingServer: false,
    timeout: 60000,
  },
});
