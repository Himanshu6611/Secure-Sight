import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

test('public routes render with one primary heading', async ({ page }) => {
  for (const [path, heading] of [
    ['/', 'Check before you trust.'],
    ['/guides/url-analysis', 'Understanding URL threat evidence'],
    ['/guides/email-analysis', 'Understanding email threat evidence'],
    ['/guides/media-analysis', 'Understanding media and provenance evidence'],
    ['/privacy', 'Privacy and data handling'],
    ['/security', 'Security limits and responsible use'],
  ]) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 })).toContainText(heading)
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze()
    expect(results.violations, `${path}: ${JSON.stringify(results.violations.map(({ id, impact, nodes }) => ({
      id, impact, targets: nodes.map(node => node.target),
    })), null, 2)}`).toEqual([])
  }
})

test('scanner modes expose labelled controls and keyboard operation', async ({ page }) => {
  await page.goto('/')
  const website = page.getByRole('tab', { name: 'Website' })
  await expect(website).toHaveAttribute('aria-selected', 'true')
  await page.getByRole('tab', { name: 'Email' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByLabel('Paste the original message')).toBeVisible()
  await expect(page.locator('input[type="file"]')).toHaveAttribute('accept', /\.eml/)
  await page.getByRole('button', { name: /Analyze/ }).focus()
  expect(await page.getByRole('button', { name: /Analyze/ }).evaluate(element => getComputedStyle(element).outlineStyle)).toBe('solid')
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('alert')).toContainText('Choose an email file or paste')
  await page.getByRole('tab', { name: 'Image' }).click()
  await expect(page.locator('input[type="file"]')).toHaveAttribute('accept', /image\/png/)
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('alert')).toContainText('Choose an image to scan')
  await expect(page.getByRole('link', { name: /Google’s SynthID Detector/ })).toHaveAttribute('rel', /noopener/)
})

test('supported email documents and image files can be selected; unsupported files are rejected', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('tab', { name: 'Email' }).click()
  const input = page.locator('input[type="file"]')
  for (const name of ['sample.eml', 'sample.pdf', 'sample.docx', 'sample.xml']) {
    await input.setInputFiles({ name, mimeType: 'application/octet-stream', buffer: Buffer.from('fixture') })
    await expect(page.getByText(name)).toBeVisible()
    await page.getByRole('button', { name: 'Remove selected file' }).click()
  }
  await input.setInputFiles({ name: 'payload.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('fixture') })
  await expect(page.getByRole('alert')).toContainText('Choose an .eml, .pdf, .docx or .xml')
  await page.getByRole('tab', { name: 'Image' }).click()
  await page.locator('input[type="file"]').setInputFiles({
    name: 'sample.png', mimeType: 'image/png', buffer: Buffer.from('fixture'),
  })
  await expect(page.getByText('sample.png')).toBeVisible()
  await page.getByRole('button', { name: 'Remove selected file' }).click()
  await page.locator('input[type="file"]').setInputFiles({
    name: 'payload.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('fixture'),
  })
  await expect(page.getByRole('alert')).toContainText('Choose a PNG, JPEG or WebP image')
})

test('validation and API failures are announced accessibly', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('alert')).toHaveText(/Enter a website address/)

  await page.getByLabel('Website address').fill('https://example.test')
  await page.route('**/api/v1/scan', route => route.fulfill({
    status: 503,
    contentType: 'application/json',
    body: JSON.stringify({ error: { message: 'Analysis is temporarily unavailable.' } }),
  }))
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('alert')).toHaveText('Analysis is temporarily unavailable.')

  await page.getByRole('tab', { name: 'Email' }).click()
  await page.locator('input[type="file"]').setInputFiles({
    name: 'notice.eml', mimeType: 'message/rfc822', buffer: Buffer.from('From: sender@example.test\n\nMessage'),
  })
  await page.route('**/api/v1/email/analyze', route => route.fulfill({
    status: 503,
    contentType: 'application/json',
    body: JSON.stringify({ error: { message: 'Email analysis is temporarily unavailable.' } }),
  }))
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('alert')).toHaveText('Email analysis is temporarily unavailable.')

  await page.getByRole('tab', { name: 'Image' }).click()
  await page.locator('input[type="file"]').setInputFiles({
    name: 'image.png', mimeType: 'image/png', buffer: Buffer.from('fixture'),
  })
  await page.route('**/api/v1/media/analyze', route => route.fulfill({
    status: 503,
    contentType: 'application/json',
    body: JSON.stringify({ error: { message: 'Image analysis is temporarily unavailable.' } }),
  }))
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('alert')).toHaveText('Image analysis is temporarily unavailable.')
})

test('scan loading and result states are announced and explain uncertainty', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Website address').fill('https://example.test')
  let releaseResponse!: () => void
  const held = new Promise<void>(resolve => { releaseResponse = resolve })
  await page.route('**/api/v1/scan', async route => {
    await held
    await route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        type: 'url',
        analysis_target: 'https://example.test/',
        assessment: { verdict: 'UNKNOWN', risk_score: null, severity: 'UNKNOWN', warnings: [], missing_signals: ['DNS_UNAVAILABLE'] },
      }),
    })
  })
  await page.getByRole('button', { name: /Analyze/ }).click()
  await expect(page.getByRole('status')).toContainText('Checking available evidence')
  releaseResponse()
  await expect(page.getByRole('heading', { name: 'Needs review' })).toBeVisible()
  await page.getByRole('button', { name: 'Evidence and limits' }).click()
  await expect(page.getByText('Unavailable evidence:')).toBeVisible()
})

test('mobile layout has no horizontal overflow and controls stay visible', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 })
  await page.goto('/')
  await expect(page.getByRole('button', { name: /Analyze/ })).toBeInViewport()
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }))
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport)
})

test('main scanner page meets automated WCAG 2.1 A/AA checks', async ({ page }) => {
  await page.goto('/')
  for (const mode of ['Website', 'Email', 'Image']) {
    if (mode !== 'Website') await page.getByRole('tab', { name: mode }).click()
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze()
    expect(results.violations, `${mode}: ${JSON.stringify(results.violations.map(({ id, impact, nodes }) => ({
      id, impact, targets: nodes.map(node => node.target),
    })), null, 2)}`).toEqual([])
  }
})
