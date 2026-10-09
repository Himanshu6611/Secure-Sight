import { defineConfig, devices } from '@playwright/test'
import { resolve } from 'node:path'

const port = Number(process.env.SECURESIGHT_E2E_PORT ?? 5101)
const baseURL = `http://127.0.0.1:${port}`
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
const pythonPath = process.env.SECURESIGHT_E2E_PYTHON ?? resolve(
  process.cwd(),
  process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python',
)

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['json', { outputFile: '../reports/phase14_20261009/browser_e2e.json' }],
  ],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    ...devices['Desktop Chrome'],
    launchOptions: executablePath ? { executablePath } : {},
  },
  webServer: {
    command: `"${pythonPath}" -m flask --app app.app run --host 127.0.0.1 --port ${port}`,
    cwd: resolve(process.cwd(), '..'),
    url: `${baseURL}/api/v1/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: 'ignore',
    env: {
      APP_ENV: 'testing',
      FLASK_SECRET_KEY: '',
      FLASK_SECRET_KEY_FILE: '',
      DASHBOARD_ENCRYPTION_KEY: '',
      DASHBOARD_ENCRYPTION_KEY_FILE: '',
      RATELIMIT_STORAGE_URI: 'memory://',
      RATELIMIT_STORAGE_URI_FILE: '',
      SITE_URL: baseURL,
      TRUSTED_HOSTS: `127.0.0.1,localhost`,
      ALLOWED_ORIGINS: '',
      SEO_INDEXING_ENABLED: 'false',
    },
  },
})
